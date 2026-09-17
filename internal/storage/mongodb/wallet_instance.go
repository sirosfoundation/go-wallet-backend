package mongodb

import (
	"context"
	"fmt"
	"time"

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
		// suspended/revoked instance. The tenant is fixed at insert as well:
		// wallet instances are per tenant, and a later attestation from
		// another tenant must not move the lifecycle record (callers read the
		// record back and refuse a mismatch, see WIAService.signWIA).
		"$setOnInsert": bson.M{
			"created_at": instance.CreatedAt,
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

	opts := options.Update().SetUpsert(true)
	_, err := s.collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("%w: upsert wallet instance: %v", storage.ErrDatabase, err)
	}

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
		bindFilter := bson.M{"_id": instance.ID, "tenant_id": instance.TenantID, "$or": []bson.M{
			{"user_id": bson.M{"$exists": false}},
			{"user_id": nil},
		}}
		if _, err := s.collection.UpdateOne(ctx, bindFilter, bson.M{"$set": bson.M{"user_id": instance.UserID}}); err != nil {
			return fmt.Errorf("%w: bind wallet instance user: %v", storage.ErrDatabase, err)
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
	// whether suspending the instance also locks that passkey out
	// (SID-AUTH-06), so a racer whose own bind lost must not be able to write
	// its credential id onto the winner's record. An unauthenticated
	// attestation carries no user to check against and keeps the plain
	// first-link-wins rule; it cannot claim a credential id in practice,
	// GenerateWIA refuses one without an authenticated caller.
	if instance.CredentialID != "" {
		linkFilter := bson.M{
			"_id":       instance.ID,
			"tenant_id": instance.TenantID,
			"$or": []bson.M{
				{"credential_id": bson.M{"$exists": false}},
				{"credential_id": ""},
			},
		}
		if instance.UserID != nil {
			linkFilter["user_id"] = *instance.UserID
		}
		if _, err := s.collection.UpdateOne(ctx, linkFilter, bson.M{"$set": bson.M{"credential_id": instance.CredentialID}}); err != nil {
			return fmt.Errorf("%w: link wallet instance credential: %v", storage.ErrDatabase, err)
		}
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

func (s *WalletInstanceStore) UpdateStatus(ctx context.Context, id string, status domain.InstanceStatus, reason string) error {
	now := time.Now().UTC()

	// Use a conditional filter to enforce valid state transitions atomically.
	// Revoked instances cannot transition to any other state.
	filter := bson.M{"_id": id}
	switch status {
	case domain.InstanceStatusActive:
		// Only suspended → active is allowed (not revoked → active).
		filter["status"] = domain.InstanceStatusSuspended
	case domain.InstanceStatusSuspended:
		// Only active → suspended is allowed.
		filter["status"] = domain.InstanceStatusActive
	case domain.InstanceStatusRevoked:
		// active → revoked and suspended → revoked are both allowed.
		filter["status"] = bson.M{"$in": []domain.InstanceStatus{domain.InstanceStatusActive, domain.InstanceStatusSuspended}}
	default:
		// Reject anything other than the three known statuses — otherwise the
		// filter above stays unconstrained ({_id: id} only) and this would
		// write an arbitrary status with no transition check at all.
		return fmt.Errorf("%w: unknown wallet instance status %q", domain.ErrInvalidStatusTransition, status)
	}

	update := bson.M{
		"$set": bson.M{
			"status":              status,
			"deactivation_reason": reason,
			"updated_at":          now,
		},
	}
	if status == domain.InstanceStatusSuspended || status == domain.InstanceStatusRevoked {
		update["$set"].(bson.M)["deactivated_at"] = now
	} else {
		update["$unset"] = bson.M{"deactivated_at": "", "deactivation_reason": ""}
	}

	res, err := s.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("%w: update wallet instance status: %v", storage.ErrDatabase, err)
	}
	if res.MatchedCount == 0 {
		// Distinguish "not found" from "invalid transition" by checking existence.
		count, cerr := s.collection.CountDocuments(ctx, bson.M{"_id": id})
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
