package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/gorilla/websocket"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
)

type Mempool struct {
	Transactions []*Transaction `json:"txs"`
}

func (app *InjectiveApp) CheckTx(req abci.RequestCheckTx) abci.ResponseCheckTx {
	app.LastCommitID()
	resp := app.BaseApp.CheckTx(req)
	if resp.Code == 0 {
		transaction, err := decodeTx(req.GetTx(), app.encfg)
		if err != nil {
			fmt.Println("Error decoding transaction:", err)
			return resp
		}

		mempool := Mempool{
			Transactions: []*Transaction{&transaction},
		}

		app.publisher.Publish(mempool, "mempool")
	}
	return resp
}

type Transaction struct {
	Nonce    string `json:"nonce"`
	Raw      string `json:"raw"`
	Code     uint32 `json:"code"`
	TxID     string `json:"tx_id"`
	Tx       any    `json:"tx"`
	TxResult any    `json:"tx_result"`
	Metadata any    `json:"metadata"`
}

type TxProtoGetter interface {
	GetProtoTx() *tx.Tx
}

func decodeTx(txBytes []byte, encfg EncodingConfig) (Transaction, error) {
	var transaction Transaction

	txproto, err := encfg.TxConfig.TxDecoder()(txBytes)
	if err != nil {
		return transaction, fmt.Errorf("DELIVERTX DECODER ERR: %w", err)
	}

	getter, ok := txproto.(TxProtoGetter)
	if !ok {
		return transaction, fmt.Errorf("failed to assert TxProtoGetter")
	}

	tx := getter.GetProtoTx()
	b, err := encfg.Marshaler.MarshalJSON(tx)
	if err != nil {
		return transaction, fmt.Errorf("failed to marshal tx: %w", err)
	}

	err = json.Unmarshal(b, &transaction.Tx)
	if err != nil {
		return transaction, fmt.Errorf("failed to unmarshal tx: %w", err)
	}

	return transaction, nil
}

func (app *InjectiveApp) DeliverTx(req abci.RequestDeliverTx) abci.ResponseDeliverTx {
	transaction, err := decodeTx(req.GetTx(), app.encfg)
	if err != nil {
		fmt.Println(err)
	}

	app.publisher.Publish(transaction, "tx")

	resp := app.BaseApp.DeliverTx(req)
	return resp
}

type Block struct {
	Nonce string `json:"nonce"`
	Block any    `json:"block"`
}

type BlockProposal struct {
	Txs                [][]any
	ProposedLastCommit any
	Hash               []byte
	Height             int64
	Time               time.Time
	NextValidatorsHash []byte
	ProposerAddress    []byte
}

func decodeTxs(txBytes [][]byte, encfg EncodingConfig) ([]Transaction, error) {
	var transactions []Transaction

	for _, bytes := range txBytes {
		tx, err := decodeTx(bytes, encfg)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, tx)
	}

	return transactions, nil
}

func (app *InjectiveApp) ProcessProposal(proposal abci.RequestProcessProposal) abci.ResponseProcessProposal {
	decodedTxs, err := decodeTxs(proposal.Txs, app.encfg)
	if err != nil {
		fmt.Println("Error decoding transactions:", err)
	}

	var txs [][]any
	for _, decodedTx := range decodedTxs {
		txs = append(txs, []any{decodedTx})
	}
	block := BlockProposal{
		Txs:                txs,
		ProposedLastCommit: proposal.ProposedLastCommit,
		Hash:               proposal.Hash,
		Height:             proposal.Height,
		Time:               proposal.Time,
		NextValidatorsHash: proposal.NextValidatorsHash,
		ProposerAddress:    proposal.ProposerAddress,
	}

	app.publisher.Publish(block, "proposed_block")

	resp := app.BaseApp.ProcessProposal(proposal)
	if resp.Status == abci.ResponseProcessProposal_ACCEPT {
		app.publisher.Publish(block, "proposed_block_accept")
	}
	return resp
}

type BlockDataOutput struct {
	Result struct {
		Data struct {
			Type  string `json:"type"`
			Value struct {
				Block struct {
					Header struct {
						Version struct {
							Block string `json:"block"`
						} `json:"version"`
						ChainID     string    `json:"chain_id"`
						Height      string    `json:"height"`
						Time        time.Time `json:"time"`
						LastBlockID struct {
							Hash  string `json:"hash"`
							Parts struct {
								Total int    `json:"total"`
								Hash  string `json:"hash"`
							} `json:"parts"`
						} `json:"last_block_id"`
						LastCommitHash     string `json:"last_commit_hash"`
						DataHash           string `json:"data_hash"`
						ValidatorsHash     string `json:"validators_hash"`
						NextValidatorsHash string `json:"next_validators_hash"`
						ConsensusHash      string `json:"consensus_hash"`
						AppHash            string `json:"app_hash"`
						LastResultsHash    string `json:"last_results_hash"`
						EvidenceHash       string `json:"evidence_hash"`
						ProposerAddress    string `json:"proposer_address"`
					} `json:"header"`
					Data struct {
						Txs []Transaction `json:"txs"`
					} `json:"data"`
					Evidence struct {
						Evidence []any `json:"evidence"`
					} `json:"evidence"`
					LastCommit struct {
						Height  string `json:"height"`
						Round   int    `json:"round"`
						BlockID struct {
							Hash  string `json:"hash"`
							Parts struct {
								Total int    `json:"total"`
								Hash  string `json:"hash"`
							} `json:"parts"`
						} `json:"block_id"`
						Signatures []struct {
							BlockIDFlag      int       `json:"block_id_flag"`
							ValidatorAddress string    `json:"validator_address"`
							Timestamp        time.Time `json:"timestamp"`
							Signature        string    `json:"signature"`
						} `json:"signatures"`
					} `json:"last_commit"`
				} `json:"block"`
			} `json:"value"`
		} `json:"data"`
	} `json:"result"`
}

type BlockData struct {
	Result struct {
		Data struct {
			Type  string `json:"type"`
			Value struct {
				Block struct {
					Header struct {
						Version struct {
							Block string `json:"block"`
						} `json:"version"`
						ChainID     string    `json:"chain_id"`
						Height      string    `json:"height"`
						Time        time.Time `json:"time"`
						LastBlockID struct {
							Hash  string `json:"hash"`
							Parts struct {
								Total int    `json:"total"`
								Hash  string `json:"hash"`
							} `json:"parts"`
						} `json:"last_block_id"`
						LastCommitHash     string `json:"last_commit_hash"`
						DataHash           string `json:"data_hash"`
						ValidatorsHash     string `json:"validators_hash"`
						NextValidatorsHash string `json:"next_validators_hash"`
						ConsensusHash      string `json:"consensus_hash"`
						AppHash            string `json:"app_hash"`
						LastResultsHash    string `json:"last_results_hash"`
						EvidenceHash       string `json:"evidence_hash"`
						ProposerAddress    string `json:"proposer_address"`
					} `json:"header"`
					Data struct {
						Txs []string `json:"txs"`
					} `json:"data"`
					Evidence struct {
						Evidence []any `json:"evidence"`
					} `json:"evidence"`
					LastCommit struct {
						Height  string `json:"height"`
						Round   int    `json:"round"`
						BlockID struct {
							Hash  string `json:"hash"`
							Parts struct {
								Total int    `json:"total"`
								Hash  string `json:"hash"`
							} `json:"parts"`
						} `json:"block_id"`
						Signatures []struct {
							BlockIDFlag      int       `json:"block_id_flag"`
							ValidatorAddress string    `json:"validator_address"`
							Timestamp        time.Time `json:"timestamp"`
							Signature        string    `json:"signature"`
						} `json:"signatures"`
					} `json:"last_commit"`
				} `json:"block"`
			} `json:"value"`
		} `json:"data"`
	} `json:"result"`
}

func (app *InjectiveApp) PublishBlocks() {
	time.Sleep(5 * time.Second)

	conn, _, _ := websocket.DefaultDialer.Dial("ws://localhost:26657/websocket", nil)

	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"jsonrpc":"2.0","method":"subscribe","params":{"query":"tm.event='NewBlock'"},"id":"1"}`))
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("read:", err)
			break
		}

		var eventMsg BlockDataOutput
		var txsstring BlockData

		err = json.Unmarshal(message, &txsstring)
		if err != nil {
			fmt.Println("error unmarshaling message:", err)
			continue
		}

		// Convert base64-encoded strings to []byte for decoding
		var txBytes [][]byte
		for _, txStr := range txsstring.Result.Data.Value.Block.Data.Txs {
			txBytesDecoded, err := base64.StdEncoding.DecodeString(txStr)
			if err != nil {
				fmt.Println("error decoding tx base64 string:", err)
				continue
			}
			txBytes = append(txBytes, txBytesDecoded)
		}
		// Decode the transactions
		decodedTxs, err := decodeTxs(txBytes, app.encfg) // Assuming `encfg` is defined and accessible
		if err != nil {
			fmt.Println("error decoding txs:", err)
			continue
		}

		txsstring.Result.Data.Value.Block.Data.Txs = nil
		temp, _ := json.Marshal(txsstring)
		err = json.Unmarshal(temp, &eventMsg)
		eventMsg.Result.Data.Value.Block.Data.Txs = decodedTxs
		app.publisher.Publish(eventMsg.Result.Data.Value.Block, "block")
	}
}
