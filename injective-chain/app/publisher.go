package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	injcodectypes "github.com/InjectiveLabs/injective-core/injective-chain/codec/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/gorilla/websocket"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"os"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
)

type Mempool struct {
	Transactions []*Transaction `json:"txs"`
}

func generateTxId(txBytes []byte) string {
	hash := sha256.Sum256(txBytes)
	return hex.EncodeToString(hash[:])
}

func (app *InjectiveApp) CheckTx(req *abci.RequestCheckTx) (*abci.ResponseCheckTx, error) {
	app.LastCommitID()
	resp, _ := app.BaseApp.CheckTx(req)
	transaction, err := decodeTx(req.GetTx(), app.encfg)
	if err != nil {
		fmt.Println("Error decoding transaction:", err)
		return resp, err
	}

	txId := generateTxId(req.GetTx())

	mempool := Mempool{
		Transactions: []*Transaction{&transaction},
	}
	mempool.Transactions[0].TxID = txId // assign generated txId
	app.publisher.Publish(mempool, "mempool")
	return resp, nil
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

func decodeTx(txBytes []byte, encfg injcodectypes.EncodingConfig) (Transaction, error) {
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
	b, err := encfg.Codec.MarshalJSON(tx)
	if err != nil {
		return transaction, fmt.Errorf("failed to marshal tx: %w", err)
	}
	err = json.Unmarshal(b, &transaction.Tx)
	if err != nil {
		return transaction, fmt.Errorf("failed to unmarshal tx: %w", err)
	}

	txId := generateTxId(txBytes)

	transaction.TxID = txId

	return transaction, nil
}

type Block struct {
	Nonce string `json:"nonce"`
	Block any    `json:"block"`
}

type BlockProposal struct {
	Txs                [][]any   `json:"txs"`
	ProposedLastCommit any       `json:"proposed_last_commit"`
	Hash               []byte    `json:"hash"`
	Height             int64     `json:"height"`
	Time               time.Time `json:"time"`
	NextValidatorsHash []byte    `json:"next_validators_hash"`
	ProposerAddress    []byte    `json:"proposer_address"`
}

func decodeTxs(txBytes [][]byte, encfg injcodectypes.EncodingConfig) ([]Transaction, error) {
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

func (app *InjectiveApp) ProcessProposal(req *abci.RequestProcessProposal) (resp *abci.ResponseProcessProposal, err error) {
	decodedTxs, err := decodeTxs(req.Txs, app.encfg)
	if err != nil {
		fmt.Println("Error decoding transactions:", err)
	}

	var txs [][]any
	for _, decodedTx := range decodedTxs {
		txs = append(txs, []any{decodedTx})
	}
	block := BlockProposal{
		Txs:                txs,
		ProposedLastCommit: req.ProposedLastCommit,
		Hash:               req.Hash,
		Height:             req.Height,
		Time:               req.Time,
		NextValidatorsHash: req.NextValidatorsHash,
		ProposerAddress:    req.ProposerAddress,
	}

	app.publisher.Publish(block, "proposed_block")

	resp, err = app.BaseApp.ProcessProposal(req)
	return resp, err
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

func (app *InjectiveApp) establishWebSocketConnection() (*websocket.Conn, error) {
	retryDelay := 1 * time.Second     // Initial delay
	const maxDelay = 60 * time.Second // Maximum delay

	WS_URL := os.Getenv("RPC_WS_URL")
	if WS_URL == "" {
		WS_URL = "ws://localhost:26657/websocket"
	}

	for {
		conn, _, err := websocket.DefaultDialer.Dial(WS_URL, nil)
		if err != nil {
			fmt.Println("error connecting to WebSocket:", err)
			time.Sleep(retryDelay)
			if retryDelay < maxDelay {
				retryDelay *= 2
			}
			continue
		}
		return conn, nil
	}
}

func (app *InjectiveApp) SubscribeToEvents(conn *websocket.Conn, events ...string) error {
	for _, event := range events {
		subscribeMessage := fmt.Sprintf(`{"jsonrpc":"2.0","method":"subscribe","params":{"query":"tm.event='%s'"},"id":"%s"}`, event, event)
		err := conn.WriteMessage(websocket.TextMessage, []byte(subscribeMessage))
		if err != nil {
			return fmt.Errorf("failed to subscribe to event %s: %w", event, err)
		}
	}
	return nil
}

func (app *InjectiveApp) StartWebSocketListener(conn *websocket.Conn) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("read:", err)
			break
		}

		var baseEvent map[string]interface{}
		err = json.Unmarshal(message, &baseEvent)
		if err != nil {
			fmt.Println("error unmarshaling message:", err)
			continue
		}

		if result, ok := baseEvent["result"].(map[string]interface{}); ok {
			if data, ok := result["data"].(map[string]interface{}); ok {
				if value, ok := data["value"].(map[string]interface{}); ok {
					if _, ok := value["TxResult"]; ok {
						// Handle Tx event
						var txEvent struct {
							Result struct {
								Data struct {
									Value struct {
										TxResult struct {
											Tx string `json:"Tx"`
										} `json:"TxResult"`
									} `json:"value"`
								} `json:"data"`
							} `json:"result"`
						}

						err = json.Unmarshal(message, &txEvent)
						if err != nil {
							fmt.Println("error unmarshaling tx message:", err)
							continue
						}

						// Decode the transaction
						txBytes, err := base64.StdEncoding.DecodeString(txEvent.Result.Data.Value.TxResult.Tx)
						if err != nil {
							fmt.Println("error decoding tx base64 string:", err)
							continue
						}
						decodedTx, err := decodeTx(txBytes, app.encfg)
						if err != nil {
							fmt.Println("error decoding tx:", err)
							continue
						}

						// Publish the transaction
						app.publisher.Publish(decodedTx, "tx")
					} else if _, ok := value["block"]; ok {
						// Handle Block event
						var blockEvent BlockDataOutput
						var txsstring BlockData

						err = json.Unmarshal(message, &txsstring)
						if err != nil {
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
						decodedTxs, err := decodeTxs(txBytes, app.encfg)
						if err != nil {
							fmt.Println("error decoding txs:", err)
							continue
						}

						txsstring.Result.Data.Value.Block.Data.Txs = nil
						temp, _ := json.Marshal(txsstring)
						err = json.Unmarshal(temp, &blockEvent)
						blockEvent.Result.Data.Value.Block.Data.Txs = decodedTxs
						app.publisher.Publish(blockEvent.Result.Data.Value.Block, "block")
					}
				}
			}
		}
	}
}

func (app *InjectiveApp) PublishBlocksAndTxs() {
	conn, err := app.establishWebSocketConnection()
	if err != nil {
		fmt.Println("Failed to establish WebSocket connection:", err)
		return
	}
	defer conn.Close()

	err = app.SubscribeToEvents(conn, "NewBlock", "Tx")
	if err != nil {
		fmt.Println("Failed to subscribe to events:", err)
		return
	}

	app.StartWebSocketListener(conn)
}

// CreateUser creates NATS user NKey and JWT from given account seed NKey.
func CreateUser(seed string) (*string, *string, error) {
	accountSeed := []byte(seed)

	accountKeys, err := nkeys.FromSeed(accountSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get account key from seed: %w", err)
	}

	accountPubKey, err := accountKeys.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting public key: %w", err)
	}

	userKeys, err := nkeys.CreateUser()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create account key: %w", err)
	}

	userSeed, err := userKeys.Seed()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get seed: %w", err)
	}
	nkey := string(userSeed)

	userPubKey, err := userKeys.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot get user's public key: %w", err)
	}

	claims := jwt.NewUserClaims(userPubKey)
	claims.Issuer = accountPubKey
	jwt, err := claims.Encode(accountKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding token to jwt: %w", err)
	}

	return &nkey, &jwt, nil
}
