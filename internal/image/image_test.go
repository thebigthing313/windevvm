package image

import "testing"

func TestFindSum(t *testing.T) {
	sums := "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94 *noble-server-cloudimg-amd64.img\n" +
		"1111111111111111111111111111111111111111111111111111111111111111 *noble-server-cloudimg-amd64-azure.vhd.tar.gz\n"
	got, err := findSum(sums, "noble-server-cloudimg-amd64.img")
	if err != nil || got != "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94" {
		t.Fatalf("findSum = %q, %v", got, err)
	}
	if _, err := findSum(sums, "missing.img"); err == nil {
		t.Fatal("expected an error")
	}
}
