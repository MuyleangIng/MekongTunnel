package handlers

import "testing"

func TestParseKomaCheckoutPage(t *testing.T) {
	html := `
		<html>
			<script>
				var qrDataUrl = "data:image/png;base64,abc123";
				var transactionId = "tran_test_123";
				var md5 = "md5_test_123";
				var pollToken = "poll_test_123";
			</script>
		</html>
	`

	got := parseKomaCheckoutPage(html)
	if got == nil {
		t.Fatal("expected checkout session")
	}
	if got.TransactionID != "tran_test_123" {
		t.Fatalf("transaction id = %q", got.TransactionID)
	}
	if got.MD5 != "md5_test_123" {
		t.Fatalf("md5 = %q", got.MD5)
	}
	if got.PollToken != "poll_test_123" {
		t.Fatalf("poll token = %q", got.PollToken)
	}
	if got.QRDataURL != "data:image/png;base64,abc123" {
		t.Fatalf("qr data url = %q", got.QRDataURL)
	}
}

func TestDeriveKomaPhase(t *testing.T) {
	scannedCode := 2
	failedCode := 3

	tests := []struct {
		name        string
		orderStatus string
		payload     *komaStatusEnvelope
		want        string
	}{
		{
			name:        "confirmed payment",
			orderStatus: "pending",
			payload: &komaStatusEnvelope{
				Data: &komaStatusData{ResponseCode: 0},
			},
			want: "paid",
		},
		{
			name:        "scanned awaiting bank",
			orderStatus: "pending",
			payload: &komaStatusEnvelope{
				Data: &komaStatusData{ResponseCode: 1, ErrorCode: &scannedCode},
			},
			want: "scanned",
		},
		{
			name:        "failed payment",
			orderStatus: "pending",
			payload: &komaStatusEnvelope{
				Data: &komaStatusData{ResponseCode: 1, ErrorCode: &failedCode},
			},
			want: "failed",
		},
		{
			name:        "expired from message",
			orderStatus: "pending",
			payload: &komaStatusEnvelope{
				Data:  &komaStatusData{ResponseMessage: "QR has expired"},
				Error: "",
			},
			want: "expired",
		},
		{
			name:        "transport error stays pending",
			orderStatus: "pending",
			payload:     &komaStatusEnvelope{Error: "temporary upstream error"},
			want:        "pending",
		},
		{
			name:        "terminal paid order stays paid",
			orderStatus: "paid",
			payload:     &komaStatusEnvelope{Error: "should be ignored"},
			want:        "paid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveKomaPhase(tt.orderStatus, tt.payload); got != tt.want {
				t.Fatalf("deriveKomaPhase() = %q, want %q", got, tt.want)
			}
		})
	}
}
