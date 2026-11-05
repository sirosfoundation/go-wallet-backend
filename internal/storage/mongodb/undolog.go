package mongodb

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// undoField is the bson field holding a record's undo log (storage.UndoLog): an
// array of {token, at, before}, oldest first, whose last entry is the write that
// set the record's current write_token. Documents written before it existed lack
// the field and keep the previous behaviour (a rollback matches the current
// write token and nothing else). The log is stored beside the record's own
// fields and is never part of a domain struct, so it cannot reach an API
// response or an export.
const undoField = "undo_log"

// undoClock returns the current time for the undo log; a store's now field
// overrides it in tests.
func undoClock(now func() time.Time) time.Time {
	if now != nil {
		return now().UTC()
	}
	return time.Now().UTC()
}

func undoCutoff(now time.Time) time.Time { return now.Add(-storage.UndoLogMaxAge) }

// loggedWrite matches a document whose undo log holds this write token, not yet
// expired.
func loggedWrite(token string, now time.Time) bson.M {
	return bson.M{undoField: bson.M{"$elemMatch": bson.M{"token": token, "at": bson.M{"$gte": undoCutoff(now)}}}}
}

// headIsCreate is a $expr that holds when the newest write in the log created
// the record (its before is null).
func headIsCreate() bson.M {
	return bson.M{"$and": bson.A{
		bson.M{"$gt": bson.A{bson.M{"$size": bson.M{"$ifNull": bson.A{"$" + undoField, bson.A{}}}}, 0}},
		bson.M{"$eq": bson.A{bson.M{"$arrayElemAt": bson.A{"$" + undoField + ".before", -1}}, nil}},
	}}
}

// prunedLogExpr is the undo log with expired entries dropped.
func prunedLogExpr(now time.Time) bson.M {
	return bson.M{"$filter": bson.M{
		"input": bson.M{"$ifNull": bson.A{"$" + undoField, bson.A{}}},
		"as":    "e",
		"cond":  bson.M{"$gte": bson.A{"$$e.at", undoCutoff(now)}},
	}}
}

// pushedLogExpr is the undo log after recording a write: pruned by age, the new
// entry appended, trimmed to the newest storage.UndoLogMaxLen. before is an
// aggregation expression for the record as it is now (null for a create).
func pushedLogExpr(now time.Time, token string, before any) bson.M {
	return bson.M{"$slice": bson.A{
		bson.M{"$concatArrays": bson.A{
			prunedLogExpr(now),
			bson.A{bson.M{"token": bson.M{"$literal": token}, "at": now, "before": before}},
		}},
		-storage.UndoLogMaxLen,
	}}
}

// withoutUndoLogExpr is the current document minus its undo log: the snapshot a
// write stores as its before.
func withoutUndoLogExpr() bson.M {
	return bson.M{"$arrayToObject": bson.M{"$filter": bson.M{
		"input": bson.M{"$objectToArray": "$$ROOT"},
		"as":    "f",
		"cond":  bson.M{"$ne": bson.A{"$$f.k", undoField}},
	}}}
}

// rollbackLet evaluates in with these variables bound for rolling back the write
// token in a pipeline over the document:
//
//	log      the undo log, expired entries dropped
//	idx      the position of the write in it (-1: not there)
//	n        the log length
//	entry    the write's entry
//	isHead   it is the newest write
//	below    the entries older than it
//	spliced  the log with it removed and the next write's before set to its before
func rollbackLet(now time.Time, token string, in any) bson.M {
	tokens := bson.M{"$map": bson.M{"input": "$$log", "as": "e", "in": "$$e.token"}}
	return bson.M{"$let": bson.M{
		"vars": bson.M{"log": prunedLogExpr(now)},
		"in": bson.M{"$let": bson.M{
			"vars": bson.M{
				"n":   bson.M{"$size": "$$log"},
				"idx": bson.M{"$indexOfArray": bson.A{tokens, bson.M{"$literal": token}}},
			},
			"in": bson.M{"$let": bson.M{
				"vars": bson.M{
					"entry":  bson.M{"$arrayElemAt": bson.A{"$$log", "$$idx"}},
					"isHead": bson.M{"$eq": bson.A{"$$idx", bson.M{"$subtract": bson.A{"$$n", 1}}}},
					"below": bson.M{"$cond": bson.A{
						bson.M{"$eq": bson.A{"$$idx", 0}}, bson.A{}, bson.M{"$slice": bson.A{"$$log", "$$idx"}},
					}},
				},
				"in": bson.M{"$let": bson.M{
					"vars": bson.M{
						"spliced": bson.M{"$concatArrays": bson.A{
							"$$below",
							bson.A{bson.M{"$mergeObjects": bson.A{
								bson.M{"$arrayElemAt": bson.A{"$$log", bson.M{"$add": bson.A{"$$idx", 1}}}},
								bson.M{"before": "$$entry.before"},
							}}},
							bson.M{"$slice": bson.A{"$$log", bson.M{"$add": bson.A{"$$idx", 2}}, "$$n"}},
						}},
					},
					"in": in,
				}},
			}},
		}},
	}}
}
