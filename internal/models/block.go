package models

import (
	"encoding/json"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/unicitynetwork/aggregator-go/pkg/api"
)

// Block represents a blockchain block
type Block struct {
	Index               *api.BigInt                  `json:"index"`
	ChainID             string                       `json:"chainId"`
	ShardID             api.ShardID                  `json:"shardId"`
	Version             string                       `json:"version"`
	ForkID              string                       `json:"forkId"`
	RootHash            api.HexBytes                 `json:"rootHash"`
	PreviousBlockHash   api.HexBytes                 `json:"previousBlockHash"`
	NoDeletionProofHash api.HexBytes                 `json:"noDeletionProofHash"`
	CreatedAt           *api.Timestamp               `json:"createdAt"`
	UnicityCertificate  api.HexBytes                 `json:"unicityCertificate"`
	ParentFragment      *api.ParentInclusionFragment `json:"parentFragment,omitempty"`    // child mode only
	ParentBlockNumber   uint64                       `json:"parentBlockNumber,omitempty"` // child mode only
	Finalized           bool                         `json:"finalized"`                   // true when all data is persisted
}

// BlockBSON represents the BSON version of Block for MongoDB storage
type BlockBSON struct {
	Index               primitive.Decimal128 `bson:"index"`
	ChainID             string               `bson:"chainId"`
	ShardID             api.ShardID          `bson:"shardId"`
	Version             string               `bson:"version"`
	ForkID              string               `bson:"forkId"`
	RootHash            string               `bson:"rootHash"`
	PreviousBlockHash   string               `bson:"previousBlockHash"`
	NoDeletionProofHash string               `bson:"noDeletionProofHash,omitempty"`
	CreatedAt           time.Time            `bson:"createdAt"`
	UnicityCertificate  string               `bson:"unicityCertificate"`
	ParentFragment      string               `bson:"parentFragment,omitempty"` // child mode only
	ParentBlockNumber   string               `bson:"parentBlockNumber,omitempty"`
	Finalized           bool                 `bson:"finalized"`
}

// ToBSON converts Block to BlockBSON for MongoDB storage
func (b *Block) ToBSON() (*BlockBSON, error) {
	indexDecimal, err := primitive.ParseDecimal128(b.Index.String())
	if err != nil {
		return nil, fmt.Errorf("error converting block index to decimal-128: %w", err)
	}
	var parentFragment string
	if b.ParentFragment != nil {
		parentFragmentJSON, err := json.Marshal(b.ParentFragment)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal parent fragment: %w", err)
		}
		parentFragment = api.NewHexBytes(parentFragmentJSON).String()
	}
	var parentBlockNumber string
	if b.ParentBlockNumber != 0 {
		parentBlockNumber = fmt.Sprintf("%d", b.ParentBlockNumber)
	}
	return &BlockBSON{
		Index:               indexDecimal,
		ChainID:             b.ChainID,
		ShardID:             b.ShardID,
		Version:             b.Version,
		ForkID:              b.ForkID,
		RootHash:            b.RootHash.String(),
		PreviousBlockHash:   b.PreviousBlockHash.String(),
		NoDeletionProofHash: b.NoDeletionProofHash.String(),
		CreatedAt:           b.CreatedAt.Time,
		UnicityCertificate:  b.UnicityCertificate.String(),
		ParentFragment:      parentFragment,
		ParentBlockNumber:   parentBlockNumber,
		Finalized:           b.Finalized,
	}, nil
}

// FromBSON converts BlockBSON back to Block
func (bb *BlockBSON) FromBSON() (*Block, error) {
	index, err := api.NewBigIntFromString(bb.Index.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse index: %w", err)
	}

	rootHash, err := api.NewHexBytesFromString(bb.RootHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rootHash: %w", err)
	}

	previousBlockHash, err := api.NewHexBytesFromString(bb.PreviousBlockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previousBlockHash: %w", err)
	}

	unicityCertificate, err := api.NewHexBytesFromString(bb.UnicityCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse unicityCertificate: %w", err)
	}

	var parentFragment *api.ParentInclusionFragment
	if bb.ParentFragment != "" {
		hexBytes, err := api.NewHexBytesFromString(bb.ParentFragment)
		if err != nil {
			return nil, fmt.Errorf("failed to parse parentFragment: %w", err)
		}
		parentFragment = &api.ParentInclusionFragment{}
		if err := json.Unmarshal(hexBytes, parentFragment); err != nil {
			return nil, fmt.Errorf("failed to parse parentFragment: %w", err)
		}
	}
	var parentBlockNumber uint64
	if bb.ParentBlockNumber != "" {
		if _, err := fmt.Sscanf(bb.ParentBlockNumber, "%d", &parentBlockNumber); err != nil {
			return nil, fmt.Errorf("failed to parse parentBlockNumber: %w", err)
		}
	}

	noDeletionProofHash, err := api.NewHexBytesFromString(bb.NoDeletionProofHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse noDeletionProofHash: %w", err)
	}

	return &Block{
		Index:               index,
		ChainID:             bb.ChainID,
		ShardID:             bb.ShardID,
		Version:             bb.Version,
		ForkID:              bb.ForkID,
		RootHash:            rootHash,
		PreviousBlockHash:   previousBlockHash,
		NoDeletionProofHash: noDeletionProofHash,
		CreatedAt:           api.NewTimestamp(bb.CreatedAt),
		UnicityCertificate:  unicityCertificate,
		ParentFragment:      parentFragment,
		ParentBlockNumber:   parentBlockNumber,
		Finalized:           bb.Finalized,
	}, nil
}

// NewBlock creates a new block
func NewBlock(index *api.BigInt, chainID string, shardID api.ShardID, version, forkID string, rootHash, previousBlockHash, uc api.HexBytes) *Block {
	return &Block{
		Index:              index,
		ChainID:            chainID,
		ShardID:            shardID,
		Version:            version,
		ForkID:             forkID,
		RootHash:           rootHash,
		PreviousBlockHash:  previousBlockHash,
		CreatedAt:          api.Now(),
		UnicityCertificate: uc,
	}
}
