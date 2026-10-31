package link

import (
	"strings"
	"sync"
	"testing"
)

// A key is claimed before the task exists, and the claim is one critical
// section: two consoles racing on the same key cannot both become the
// owner.
func TestAKeyIsClaimedOnce(t *testing.T) {
	s := &Server{}
	if _, status := s.idemClaim("click-1"); status != idemOwner {
		t.Fatalf("the first claim was not the owner: %v", status)
	}
	// The reservation is live: the second console waits and is told the
	// answer is coming, not that it is the owner.
	if _, status := s.idemClaim("click-1"); status != idemBusy {
		t.Fatalf("the second claim took a key that is held: %v", status)
	}
	s.idemFinish("click-1", "t-1")
	taskID, status := s.idemClaim("click-1")
	if status != idemDone || taskID != "t-1" {
		t.Fatalf("the finished key answered %q / %v", taskID, status)
	}
}

// A submission that failed gives its key back.
func TestAFailedSubmissionGivesTheKeyBack(t *testing.T) {
	s := &Server{}
	s.idemClaim("click-2")
	s.idemAbort("click-2")
	if taskID, status := s.idemClaim("click-2"); status != idemOwner {
		t.Fatalf("the aborted key was not free again: %q / %v", taskID, status)
	}
}

// Twenty consoles ask the same question at once: one task, one answer.
func TestConcurrentClaimsOfOneKeyMakeOneTask(t *testing.T) {
	s := &Server{}
	const consoles = 20
	var wg sync.WaitGroup
	owners := make([]int, consoles)
	answers := make([]string, consoles)
	statuses := make([]idemStatus, consoles)
	start := make(chan struct{})
	for i := 0; i < consoles; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			taskID, status := s.idemClaim("same-click")
			statuses[i] = status
			answers[i] = taskID
			if status == idemOwner {
				owners[i] = 1
				s.idemFinish("same-click", "t-only")
			}
		}(i)
	}
	close(start)
	wg.Wait()

	total := 0
	for i := 0; i < consoles; i++ {
		total += owners[i]
	}
	if total != 1 {
		t.Fatalf("%d consoles became the owner of one key", total)
	}
	for i := 0; i < consoles; i++ {
		if statuses[i] == idemOwner {
			continue
		}
		if statuses[i] != idemDone {
			t.Fatalf("console %d was told %v instead of the answer", i, statuses[i])
		}
		if answers[i] != "t-only" {
			t.Fatalf("console %d got the task %q", i, answers[i])
		}
	}
}

// A long key is never cut: two keys that share a long prefix are two
// questions, and answering one with the other would hand a console the
// wrong task.
func TestALongKeyIsNotCut(t *testing.T) {
	s := &Server{}
	prefix := strings.Repeat("k", idemKeyMax)
	first := prefix + "-one"
	second := prefix + "-two"
	if len(first) <= idemKeyMax {
		t.Fatal("the test keys are not long enough")
	}
	if _, status := s.idemClaim(first); status != idemOwner {
		t.Fatalf("the first long key was refused: %v", status)
	}
	s.idemFinish(first, "t-one")
	if _, status := s.idemClaim(second); status != idemOwner {
		t.Fatalf("a second long key was taken for the first: %v", status)
	}
	s.idemFinish(second, "t-two")
	if taskID, _ := s.idemClaim(first); taskID != "t-one" {
		t.Fatalf("the first long key answered with %q", taskID)
	}
	if taskID, _ := s.idemClaim(second); taskID != "t-two" {
		t.Fatalf("the second long key answered with %q", taskID)
	}
}

// An empty key is never a key: a submission without one asks for a task.
func TestAnEmptyKeyIsNeverAKey(t *testing.T) {
	s := &Server{}
	if _, status := s.idemClaim(""); status != idemOwner {
		t.Fatalf("an empty key was claimed: %v", status)
	}
	s.idemFinish("", "t-never")
	if s.idemKeys() != 0 {
		t.Fatalf("an empty key was remembered (%d keys)", s.idemKeys())
	}
}
