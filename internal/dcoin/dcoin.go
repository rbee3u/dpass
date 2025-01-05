package dcoin

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func ReadMnemonic() (string, error) {
	mnemonic, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read mnemonic: %w", err)
	}
	return strings.Join(strings.Fields(string(mnemonic)), " "), nil
}
