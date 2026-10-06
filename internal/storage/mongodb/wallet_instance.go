package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// WalletInstanceStore implements storage.WalletInstanceStore using MongoDB.
type WalletInstanceStore struct {
	collection *mongo.Collection
}

func (s *WalletInstanceStore) Upsert(ctx context.Context, instance *domain.WalletInstance) error {
	// Scoped to the tenant, so an attestation from another tenant does not
	// even touch this record's metadata. The instance key is global while the
	// record belongs to one tenant, so a mismatch makes the upsert try to
	// insert a second document with the same _id: that duplicate key is how
	// "the record is another tenant's" reaches the caller.
	filter := bson.M{"_id": instance.ID, "tenant_id": instance.TenantID}
	update := bson.M{
		"$set": bson.M{
			"attestation_source": instance.AttestationSource,
			"last_attested_at":   instance.LastAttestedAt,
			"updated_at":         instance.UpdatedAt,
		},
		// Status is only ever set here for a brand-new document (via $setOnInsert).
		// An existing instance's status must only change through UpdateStatus —
		// otherwise a routine re-attestation would silently reactivate a
		// revoked instance. The tenant is fixed at insert as well:
		// wallet instances are per tenant, and a later attestation from
		// another tenant must not move the lifecycle record (callers read the
		// record back and refuse a mismatch, see WIAService.signWIA).
		"$setOnInsert": bson.M{
			"created_at": instance.CreatedAt,
			// A fresh generation per insert, so a record deleted and
			// attested again under the same id is a different record to a
			// conditional write (see domain.InstanceBinding).
			"generation": uuid.NewString(),
			"status":     instance.Status,
			"tenant_id":  instance.TenantID,
		},
		"$inc": bson.M{
			"attestation_count": 1,
		},
	}
	if instance.DeviceInfo != nil {
		update["$set"].(bson.M)["device_info"] = instance.DeviceInfo
	}

	// FindOneAndUpdate returns the document as written, so the generation the
	// follow-up bind and link are scoped to is the one this upsert inserted or
	// matched, not whatever a later read would find.
	var written struct {
		Generation string `bson:"generation"`
	}
	err := s.collection.FindOneAndUpdate(ctx, filter, update,
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After).
			SetProjection(bson.M{"generation": 1}),
	).Decode(&written)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("%w: upsert wallet instance: %v", storage.ErrDatabase, err)
	}
	// Reported to the caller, as the memory store does.
	instance.Generation = written.Generation

	// The user binding is written only while the document has none, so two
	// authenticated attestations of the same anonymous instance cannot both
	// "win": the second one finds user_id already set and leaves it. Callers
	// read the record back to learn who owns it (WIAService.signWIA).
	//
	// The filter is scoped to the instance's own tenant as well. tenant_id is
	// fixed at insert, so when two first attestations race after both saw a
	// missing record the loser's $setOnInsert is dropped - but without this
	// clause its bind would still land, permanently parking a user of tenant B
	// on the record tenant A created. The read-back refuses B's WIA either
	// way; this keeps A's record bindable by A's real owner.
	if instance.UserID != nil {
		res, err := s.collection.UpdateOne(ctx, upsertBindFilter(instance), bson.M{"$set": bson.M{"user_id": instance.UserID}})
		if err != nil {
			return fmt.Errorf("%w: bind wallet instance user: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 0 {
			if err := s.requireGeneration(ctx, instance); err != nil {
				return err
			}
		}
	}

	// The passkey link is client-supplied, so only the first non-empty
	// binding is recorded: the filter matches the document only while it has
	// no credential_id, which makes "first link wins" atomic and stops a later
	// attestation from moving the instance to another passkey.
	//
	// Like the bind above it is scoped to the fixed tenant, and for an
	// authenticated attestation further to the user the record ended up bound
	// to (the bind just above ran, so that is either this caller or the
	// winner of a race it lost). "First link wins" is permanent and decides
	// whether revoking the instance also locks that passkey out
	// (SID-AUTH-06), so a racer whose own bind lost must not be able to write
	// its credential id onto the winner's record. An unauthenticated
	// attestation carries no user to check against and keeps the plain
	// first-link-wins rule; it cannot claim a credential id in practice,
	// GenerateWIA refuses one without an authenticated caller.
	if instance.CredentialID != "" {
		res, err := s.collection.UpdateOne(ctx, upsertLinkFilter(instance), bson.M{"$set": bson.M{"credential_id": instance.CredentialID}})
		if err != nil {
			return fmt.Errorf("%w: link wallet instance credential: %v", storage.ErrDatabase, err)
		}
		if res.MatchedCount == 0 {
			if err := s.requireGeneration(ctx, instance); err != nil {
				return err
			}
		}
	}
	return nil
}

// generationCond matches the generation the upsert wrote: none (absent, null
// or empty) for a record that predates generations.
func generationCond(gen string) bson.M {
	if gen == "" {
		return bson.M{"$or": []bson.M{
			{"generation": bson.M{"$exists": false}},
			{"generation": nil},
			{"generation": ""},
		}}
	}
	return bson.M{"generation": gen}
}

// upsertBindFilter is the filter of Upsert's owner bind. Besides id, tenant
// and "still unowned" it carries the generation the upsert wrote: the bind
// is a separate statement, and if the record was deleted and the thumbprint
// attested again in between, an unscoped bind would match the replacement's
// empty owner and park it on this caller.
func upsertBindFilter(instance *domain.WalletInstance) bson.M {
	return bson.M{"$and": []bson.M{
		{"_id": instance.ID},
		{"tenant_id": instance.TenantID},
		generationCond(instance.Generation),
		{"$or": []bson.M{
			{"user_id": bson.M{"$exists": false}},
			{"user_id": nil},
		}},
	}}
}

// upsertLinkFilter is the filter of Upsert's passkey link; see
// upsertBindFilter for why it is scoped to the generation.
func upsertLinkFilter(instance *domain.WalletInstance) bson.M {
	conds := []bson.M{
		{"_id": instance.ID},
		{"tenant_id": instance.TenantID},
		generationCond(instance.Generation),
		{"$or": []bson.M{
			{"credential_id": bson.M{"$exists": false}},
			{"credential_id": ""},
		}},
	}
	if instance.UserID != nil {
		conds = append(conds, bson.M{"user_id": *instance.UserID})
	}
	return bson.M{"$and": conds}
}

// requireGeneration tells a follow-up write that matched nothing because the
// record is already bound or linked (fine; the caller reads it back) from one
// that matched nothing because the record is no longer the one the upsert
// wrote. The latter is ErrBindingChanged: nothing was written to the
// replacement, and the caller must refuse the attestation.
func (s *WalletInstanceStore) requireGeneration(ctx context.Context, instance *domain.WalletInstance) error {
	n, err := s.collection.CountDocuments(ctx, bson.M{"$and": []bson.M{
		{"_id": instance.ID},
		{"tenant_id": instance.TenantID},
		generationCond(instance.Generation),
	}})
	if err != nil {
		return fmt.Errorf("%w: re-check wallet instance generation: %v", storage.ErrDatabase, err)
	}
	if n == 0 {
		return storage.ErrBindingChanged
	}
	return nil
}

func (s *WalletInstanceStore) GetByID(ctx context.Context, id string) (*domain.WalletInstance, error) {
	var instance domain.WalletInstance
	err := s.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&instance)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("%w: get wallet instance: %v", storage.ErrDatabase, err)
	}
	return &instance, nil
}

func (s *WalletInstanceStore) GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.WalletInstance, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, fmt.Errorf("%w: list wallet instances: %v", storage.ErrDatabase, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var instances []*domain.WalletInstance
	if err := cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("%w: decode wallet instances: %v", storage.ErrDatabase, err)
	}
	return instances, nil
}

func (s *WalletInstanceStore) GetByUser(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) ([]*domain.WalletInstance, error) {
	filter := bson.M{
		"tenant_id": tenantID,
		"user_id":   userID,
	}
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("%w: list wallet instances by user: %v", storage.ErrDatabase, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var instances []*domain.WalletInstance
	if err := cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("%w: decode wallet instances: %v", storage.ErrDatabase, err)
	}
	return instances, nil
}

// GetAllByUser lists every instance of the user across all tenants. See the
// interface for why account deletion cannot use the per-tenant listing.
func (s *WalletInstanceStore) GetAllByUser(ctx context.Context, userID domain.UserID) ([]*domain.WalletInstance, error) {
	cursor, err := s.collection.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return nil, fmt.Errorf("%w: list wallet instances across tenants: %v", storage.ErrDatabase, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var instances []*domain.WalletInstance
	if err := cursor.All(ctx, &instances); err != nil {
		return nil, fmt.Errorf("%w: decode wallet instances: %v", storage.ErrDatabase, err)
	}
	return instances, nil
}

func (s *WalletInstanceStore) UpdateStatus(ctx context.Context, id string, tenantID domain.TenantID, status domain.InstanceStatus, reason string) error {
	return s.updateStatus(ctx, bson.M{"_id": id, "tenant_id": tenantID}, status, reason)
}

// UpdateStatusForUser is UpdateStatus with the owner in the filter too. See
// the interface for why a per-user sweep needs it.
func (s *WalletInstanceStore) UpdateStatusForUser(ctx context.Context, id string, tenantID domain.TenantID, userID domain.UserID, status domain.InstanceStatus, reason string) error {
	return s.updateStatus(ctx, bson.M{"_id": id, "tenant_id": tenantID, "user_id": userID}, status, reason)
}

// bindingFilter matches the record with this id in this tenant that still has
// the expected owner (none, for an unowned one) and generation (none, for a
// record written before generations existed). Absent, null and empty-string
// all count as "none" for both, as elsewhere in this store.
func bindingFilter(id string, tenantID domain.TenantID, b domain.InstanceBinding) bson.M {
	none := func(field string) bson.M {
		return bson.M{"$or": []bson.M{
			{field: bson.M{"$exists": false}},
			{field: nil},
			{field: ""},
		}}
	}
	conds := []bson.M{{"_id": id}, {"tenant_id": tenantID}}
	if b.Owner == nil {
		conds = append(conds, none("user_id"))
	} else {
		conds = append(conds, bson.M{"user_id": *b.Owner})
	}
	if b.Generation == "" {
		conds = append(conds, none("generation"))
	} else {
		conds = append(conds, bson.M{"generation": b.Generation})
	}
	return bson.M{"$and": conds}
}

// UpdateStatusIfUnchanged is UpdateStatus with the expected owner and
// generation in the filter. See the interface.
func (s *WalletInstanceStore) UpdateStatusIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding, status domain.InstanceStatus, reason string) error {
	err := s.updateStatus(ctx, bindingFilter(id, tenantID, expected), status, reason)
	if errors.Is(err, storage.ErrNotFound) {
		// Nothing matched the binding; tell "no such record in this tenant"
		// from "a different record now".
		count, cerr := s.collection.CountDocuments(ctx, bson.M{"_id": id, "tenant_id": tenantID})
		if cerr != nil {
			return fmt.Errorf("%w: update wallet instance status: %v", storage.ErrDatabase, cerr)
		}
		if count > 0 {
			return storage.ErrBindingChanged
		}
	}
	return err
}

// DeleteIfUnchanged deletes only while the record matches the expected owner
// and generation. See the interface.
func (s *WalletInstanceStore) DeleteIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding) error {
	res, err := s.collection.DeleteOne(ctx, bindingFilter(id, tenantID, expected))
	if err != nil {
		return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, err)
	}
	if res.DeletedCount == 0 {
		return s.missOrChanged(ctx, id, tenantID)
	}
	return nil
}

// missOrChanged classifies a conditional write that matched nothing.
func (s *WalletInstanceStore) missOrChanged(ctx context.Context, id string, tenantID domain.TenantID) error {
	count, err := s.collection.CountDocuments(ctx, bson.M{"_id": id, "tenant_id": tenantID})
	if err != nil {
		return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, err)
	}
	if count == 0 {
		return storage.ErrNotFound
	}
	return storage.ErrBindingChanged
}

// revocableSourceFilter is the status condition of a revocation: the stored
// status must be one domain.RevocableStatuses names.
func revocableSourceFilter() bson.M {
	return bson.M{"$in": domain.RevocableStatuses()}
}

// updateStatus applies the revocation to the record matching match, which
// always carries _id and tenant_id (and user_id for the owner-checked form).
func (s *WalletInstanceStore) updateStatus(ctx context.Context, match bson.M, status domain.InstanceStatus, reason string) error {
	now := time.Now().UTC()

	// Use a conditional filter to enforce the state transition atomically.
	// There is one legal transition, active → revoked, and revocation is
	// terminal.
	filter := bson.M{}
	for k, v := range match {
		filter[k] = v
	}
	switch status {
	case domain.InstanceStatusRevoked:
		// Only active and legacy suspended may be revoked (the latter is
		// what makes a record written by an earlier release closable by an
		// operator). An unknown or corrupted status matches nothing, so it
		// fails closed rather than being revoked.
		filter["status"] = revocableSourceFilter()
	default:
		// Anything else is refused here rather than left to run with an
		// unconstrained filter ({_id: id} alone), which would write the
		// status with no transition check at all. That covers an unknown
		// value and "active": an instance is active from the moment it is
		// inserted and can never be returned to it.
		return fmt.Errorf("%w: cannot set wallet instance status to %q", domain.ErrInvalidStatusTransition, status)
	}

	update := bson.M{
		"$set": bson.M{
			"status":              status,
			"deactivation_reason": reason,
			"updated_at":          now,
		},
	}
	// Only revocation reaches this point, so the timestamp is always set.
	update["$set"].(bson.M)["deactivated_at"] = now

	res, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("%w: update wallet instance status: %v", storage.ErrDatabase, err)
	}
	if res.MatchedCount == 0 {
		// Distinguish "not found" from "invalid transition" by checking existence.
		count, cerr := s.collection.CountDocuments(ctx, match)
		if cerr != nil || count == 0 {
			return storage.ErrNotFound
		}
		return domain.ErrInvalidStatusTransition
	}
	return nil
}

func (s *WalletInstanceStore) IncrementAttestation(ctx context.Context, id string) error {
	now := time.Now().UTC()
	update := bson.M{
		"$inc": bson.M{"attestation_count": 1},
		"$set": bson.M{
			"last_attested_at": now,
			"updated_at":       now,
		},
	}
	res, err := s.collection.UpdateByID(ctx, id, update)
	if err != nil {
		return fmt.Errorf("%w: increment attestation: %v", storage.ErrDatabase, err)
	}
	if res.MatchedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteIfRemovable deletes only while the instance is still removable, so a
// revocation landing between the caller's check and this delete keeps its
// tombstone. See the interface for why that record must survive.
func (s *WalletInstanceStore) DeleteIfRemovable(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding) error {
	bound := bindingFilter(id, tenantID, expected)
	filter := bson.M{"$and": []bson.M{
		bound,
		// Ownership does not decide: a non-live record is a lifecycle
		// tombstone even when no user is bound (anonymous WIA).
		{"status": domain.InstanceStatusActive},
	}}
	res, err := s.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, err)
	}
	if res.DeletedCount == 0 {
		// Tell "gone or another tenant's" and "a different record now" apart
		// from "became a tombstone".
		if err := s.missOrChanged(ctx, id, tenantID); !errors.Is(err, storage.ErrBindingChanged) {
			return err
		}
		count, cerr := s.collection.CountDocuments(ctx, bound)
		if cerr != nil {
			return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, cerr)
		}
		if count == 0 {
			return storage.ErrBindingChanged
		}
		return domain.ErrInvalidStatusTransition
	}
	return nil
}

func (s *WalletInstanceStore) Delete(ctx context.Context, id string) error {
	res, err := s.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, err)
	}
	if res.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteForUser deletes only while the record is still in tenantID and bound
// to userID, in one filtered DeleteOne. See the interface for why.
func (s *WalletInstanceStore) DeleteForUser(ctx context.Context, id string, tenantID domain.TenantID, userID domain.UserID) error {
	res, err := s.collection.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": tenantID, "user_id": userID})
	if err != nil {
		return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, err)
	}
	if res.DeletedCount == 0 {
		return storage.ErrNotFound
	}
	return nil
}
