// Command channelpay-fixtures generates deterministic wire vectors with the
// pinned official Hacash Go serializers. It intentionally has no go.mod:
// upstream Hacash ChannelPay uses the legacy GOPATH layout at the pinned
// revisions documented in README.md.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hacash/channelpay/protocol"
	"github.com/hacash/core/account"
	"github.com/hacash/core/channel"
	"github.com/hacash/core/fields"
)

const (
	channelPayCommit = "d63e4109f2f9f4471f0838536b68b240848a77ef"
	hacashCoreCommit = "8bb265fc1a68acc0af3236354fba7386bac4d9c5"
)

type manifest struct {
	SchemaVersion     uint32         `json:"schema_version"`
	Producer          string         `json:"producer"`
	ProtocolVersion   uint32         `json:"protocol_version"`
	ChannelPayCommit  string         `json:"channelpay_commit"`
	HacashCoreCommit  string         `json:"hacash_core_commit"`
	Vectors           []vectorRecord `json:"vectors"`
}

type vectorRecord struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Format      string `json:"format"`
	MessageType *uint8 `json:"message_type,omitempty"`
}

type serializable interface {
	SerializeWithType() ([]byte, error)
}

type vector struct {
	name        string
	format      string
	messageType *uint8
	bytes       []byte
}

func typePtr(value uint8) *uint8 {
	return &value
}

func mustSerialize(message serializable) []byte {
	bytes, err := message.SerializeWithType()
	if err != nil {
		panic(err)
	}
	return bytes
}

func deterministicDocuments() (*channel.ChannelPayCompleteDocuments, fields.Sign, fields.Sign) {
	left := account.GetAccountByPrivateKeyOrPassword("hpay-channelpay-fixture-left-v1")
	right := account.GetAccountByPrivateKeyOrPassword("hpay-channelpay-fixture-right-v1")
	channelID := fields.ChannelId([]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	})

	prove := channel.CreateEmptyProveBody(channelID)
	prove.ReuseVersion = fields.VarUint4(1)
	prove.BillAutoNumber = fields.VarUint8(7)
	prove.PayDirection = fields.VarUint1(channel.ChannelTransferDirectionLeftToRight)
	prove.PayAmount = *fields.NewAmountNumSmallCoin(1)
	prove.LeftBalance = *fields.NewAmountNumSmallCoin(9)
	prove.RightBalance = *fields.NewAmountNumSmallCoin(1)
	prove.LeftAddress = fields.Address(left.Address)
	prove.RightAddress = fields.Address(right.Address)

	signCount, signAddresses := channel.CleanSortMustSignAddresses([]fields.Address{
		fields.Address(left.Address),
		fields.Address(right.Address),
	})
	transfer := &channel.OffChainFormPaymentChannelTransfer{
		Timestamp:                fields.BlockTxTimestamp(1_700_000_000),
		OrderNoteHashHalfChecker: fields.HashHalfChecker([]byte("HPAY-GOLDEN-V1!!")),
		MustSignCount:            signCount,
		MustSignAddresses:        signAddresses,
		ChannelCount:             fields.VarUint1(1),
		ChannelTransferProveHashHalfCheckers: []fields.HashHalfChecker{
			prove.GetSignStuffHashHalfChecker(),
		},
		MustSigns: []fields.Sign{
			fields.CreateEmptySign(),
			fields.CreateEmptySign(),
		},
	}
	leftSign, err := transfer.DoSignFillPosition(left)
	if err != nil {
		panic(err)
	}
	rightSign, err := transfer.DoSignFillPosition(right)
	if err != nil {
		panic(err)
	}
	if err := transfer.VerifySignature(); err != nil {
		panic(err)
	}

	return &channel.ChannelPayCompleteDocuments{
		ProveBodys: &channel.ChannelPayProveBodyList{
			Count:      fields.VarUint1(1),
			ProveBodys: []*channel.ChannelChainTransferProveBodyInfo{prove},
		},
		ChainPayment: transfer,
	}, *leftSign, *rightSign
}

func vectors() []vector {
	documents, leftSign, rightSign := deterministicDocuments()
	docBytes, err := documents.Serialize()
	if err != nil {
		panic(err)
	}
	prove := documents.ProveBodys.ProveBodys[0]
	channelID := prove.ChannelId
	leftAddress := prove.LeftAddress

	signList := fields.SignListMax255{
		Count: fields.VarUint1(2),
		Signs: []fields.Sign{leftSign, rightSign},
	}
	return []vector{
		{
			name:        "heartbeat",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeHeartbeat),
			bytes:       mustSerialize(protocol.MsgHeartbeat{}),
		},
		{
			name:        "login",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeLogin),
			bytes: mustSerialize(protocol.MsgLogin{
				ProtocolVersion: fields.VarUint2(1),
				ChannelId:       channelID,
				CustomerAddress: leftAddress,
				LanguageSet:     fields.CreateStringMax255("en-US"),
			}),
		},
		{
			name:        "prequery-request",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeRequestPrequeryPayment),
			bytes: mustSerialize(protocol.MsgRequestPrequeryPayment{
				PayAmount:        *fields.NewAmountNumSmallCoin(1),
				PaySatoshi:       fields.NewEmptySatoshiVariation(),
				PayeeChannelAddr: fields.CreateStringMax255("fixture-payee__hpay"),
			}),
		},
		{
			name:        "prove-body",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeBroadcastChannelStatementProveBody),
			bytes: mustSerialize(protocol.MsgBroadcastChannelStatementProveBody{
				TransactionDistinguishId: fields.VarUint8(0x0102030405060708),
				ProveBodyIndex:           fields.VarUint1(0),
				ProveBodyInfo:            prove,
			}),
		},
		{
			name:        "signature",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeBroadcastChannelStatementSignature),
			bytes: mustSerialize(protocol.MsgBroadcastChannelStatementSignature{
				TransactionDistinguishId: fields.VarUint8(0x0102030405060708),
				Signs:                    signList,
			}),
		},
		{
			name:        "broadcast-error",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeBroadcastChannelStatementError),
			bytes: mustSerialize(protocol.MsgBroadcastChannelStatementError{
				ErrCode: fields.VarUint2(7),
				ErrTip:  fields.CreateStringMax65535("fixture-error"),
			}),
		},
		{
			name:        "broadcast-success",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeBroadcastChannelStatementSuccessed),
			bytes: mustSerialize(protocol.MsgBroadcastChannelStatementSuccessed{
				SuccessTip: fields.CreateStringMax65535("fixture-success"),
			}),
		},
		{
			name:        "reconciliation-request",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeClientInitiateReconciliation),
			bytes: mustSerialize(protocol.MsgClientInitiateReconciliation{
				SelfSign: leftSign,
			}),
		},
		{
			name:        "reconciliation-response",
			format:      "protocol_frame",
			messageType: typePtr(protocol.MsgTypeServicerRespondReconciliation),
			bytes: mustSerialize(protocol.MsgServicerRespondReconciliation{
				SelfSign: rightSign,
			}),
		},
		{
			name:   "complete-documents",
			format: "complete_documents",
			bytes:  docBytes,
		},
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: channelpay-fixtures <output-directory>")
		os.Exit(2)
	}
	output := os.Args[1]
	if err := os.MkdirAll(output, 0o755); err != nil {
		panic(err)
	}

	generated := vectors()
	records := make([]vectorRecord, 0, len(generated))
	for _, item := range generated {
		filename := item.name + ".bin"
		path := filepath.Join(output, filename)
		if err := os.WriteFile(path, item.bytes, 0o644); err != nil {
			panic(err)
		}
		digest := sha256.Sum256(item.bytes)
		records = append(records, vectorRecord{
			Name:        item.name,
			Path:        filename,
			SHA256:      hex.EncodeToString(digest[:]),
			Format:      item.format,
			MessageType: item.messageType,
		})
	}

	data, err := json.MarshalIndent(manifest{
		SchemaVersion:    1,
		Producer:         "official-hacash-channelpay-go",
		ProtocolVersion:  1,
		ChannelPayCommit: channelPayCommit,
		HacashCoreCommit: hacashCoreCommit,
		Vectors:          records,
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(output, "manifest.json"), data, 0o644); err != nil {
		panic(err)
	}
}
