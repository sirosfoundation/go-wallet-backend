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
	// Tenant-scoped: a mismatch inserts a duplicate _id, and that duplicate-key
	// error is how "another tenant's record" reaches the caller.
	filter := bson.M{"_id": instance.ID, "tenant_id": instance.TenantID}
	update := bson.M{
		"$set": bson.M{
			"attestation_source": instance.AttestationSource,
			"last_attested_at":   instance.LastAttestedAt,
			"updated_at":         instance.UpdatedAt,
		},
		// Status and tenant are fixed at insert: re-attestation must not reactivate
		// a revoked instance or move it to another tenant.
		"$setOnInsert": bson.M{
			"created_at": instance.CreatedAt,
			// Fresh generation per insert (domain.InstanceBinding).
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

	// Bind and link are scoped to the generation this upsert wrote or matched.
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
	instance.Generation = written.Generation

	// Bind only while unowned and scoped to the tenant, so racing attestations
	// cannot both win and a foreign user is not parked on this record.
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

	// Only the first non-empty passkey link is recorded (credential_id unset),
	// scoped like the bind, so a racer whose bind lost cannot link its credential
	// to the winner's record (SID-AUTH-06).
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

// generationCond matches the generation the upsert wrote (none for legacy records).
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

// upsertBindFilter is Upsert's owner-bind filter: id, tenant, unowned and generation.
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

// upsertLinkFilter is Upsert's passkey-link filter, scoped like upsertBindFilter.
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

// requireGeneration separates "already bound or linked" (fine) from "no longer
// the record the upsert wrote" (ErrBindingChanged).
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

// GetAllByUser lists every instance of the user across all tenants.
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

// UpdateStatusForUser is UpdateStatus with the owner in the filter too.
func (s *WalletInstanceStore) UpdateStatusForUser(ctx context.Context, id string, tenantID domain.TenantID, userID domain.UserID, status domain.InstanceStatus, reason string) error {
	return s.updateStatus(ctx, bson.M{"_id": id, "tenant_id": tenantID, "user_id": userID}, status, reason)
}

// bindingFilter matches id, tenant, expected owner and generation (absent, null, "" mean none).
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

// UpdateStatusIfUnchanged is UpdateStatus conditional on owner and generation.
func (s *WalletInstanceStore) UpdateStatusIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding, status domain.InstanceStatus, reason string) error {
	err := s.updateStatus(ctx, bindingFilter(id, tenantID, expected), status, reason)
	if errors.Is(err, storage.ErrNotFound) {
		// Distinguish "no such record" from "a different record now".
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

// DeleteIfUnchanged deletes only while owner and generation match.
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

// revocableSourceFilter requires a status in domain.RevocableStatuses.
func revocableSourceFilter() bson.M {
	return bson.M{"$in": domain.RevocableStatuses()}
}

// updateStatus revokes the record matching match (always _id and tenant_id).
func (s *WalletInstanceStore) updateStatus(ctx context.Context, match bson.M, status domain.InstanceStatus, reason string) error {
	now := time.Now().UTC()

	// The filter enforces the one legal transition (active to revoked) atomically.
	filter := bson.M{}
	for k, v := range match {
		filter[k] = v
	}
	switch status {
	case domain.InstanceStatusRevoked:
		// Active and legacy suspended may be revoked; an unknown status matches
		// nothing (fail closed).
		filter["status"] = revocableSourceFilter()
	default:
		// Anything else is refused: an unconstrained filter would skip the transition check.
		return fmt.Errorf("%w: cannot set wallet instance status to %q", domain.ErrInvalidStatusTransition, status)
	}

	update := bson.M{
		"$set": bson.M{
			"status":              status,
			"deactivation_reason": reason,
			"updated_at":          now,
		},
	}
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

// DeleteIfRemovable deletes only while the instance is removable, so a
// concurrent revocation keeps its tombstone.
func (s *WalletInstanceStore) DeleteIfRemovable(ctx context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding) error {
	bound := bindingFilter(id, tenantID, expected)
	filter := bson.M{"$and": []bson.M{
		bound,
		{"status": domain.InstanceStatusActive},
	}}
	res, err := s.collection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("%w: delete wallet instance: %v", storage.ErrDatabase, err)
	}
	if res.DeletedCount == 0 {
		// Distinguish gone/foreign, a different record, and "became a tombstone".
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

// DeleteForUser deletes only while the record is in tenantID and bound to userID.
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
