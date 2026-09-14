package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// nextSequence atomically increments the named counter document and returns
// the new value, creating the counter on first use. The update must return
// the document *after* the increment: with the driver default (before) the
// first two callers on a fresh database both receive 1 and the second insert
// fails with a duplicate _id.
func nextSequence(ctx context.Context, counters *mongo.Collection, key string) (int64, error) {
	var doc struct {
		Value int64 `bson:"value"`
	}
	err := counters.FindOneAndUpdate(ctx,
		bson.M{"_id": key},
		bson.M{"$inc": bson.M{"value": 1}},
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	).Decode(&doc)
	if err != nil {
		return 0, fmt.Errorf("next %s: %w", key, err)
	}
	return doc.Value, nil
}
