package seal

import coreseal "github.com/mscno/esec/pkg/seal"

// RecordsFile names the shared signed seal manifest.
const RecordsFile = coreseal.RecordsFile

// Record is a signed record shared with the core reader.
type Record = coreseal.Record

// SealedFor identifies one reader and its recipients.
type SealedFor = coreseal.SealedFor

// Records indexes the shared records by environment.
type Records = coreseal.Records

// LoadRecords reads signed seal metadata without opening keys.
func LoadRecords(root string) (Records, error) { return coreseal.LoadRecords(root) }

// ParseRecords decodes the shared signed seal manifest.
func ParseRecords(data []byte) (Records, error) { return coreseal.ParseRecords(data) }
