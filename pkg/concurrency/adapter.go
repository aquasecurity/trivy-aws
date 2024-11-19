package concurrency

import (
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/trivy-aws/pkg/progress"
)

type Context interface {
	ConcurrencyStrategy() Strategy
	Tracker() progress.ServiceTracker
}

func Adapt[T any, S any](items []T, ctx Context, adapt func(T) (*S, error)) []S {
	return AdaptWithState(items, nil, ctx, func(item T, _ *state.State) (*S, error) {
		return adapt(item)
	})
}

func AdaptWithState[T any, S any](items []T, currentState *state.State, ctx Context, adapt func(T, *state.State) (*S, error)) []S {
	processes := getProcessCount(ctx.ConcurrencyStrategy())

	// TODO: use InfoContext
	log.Info("Start concurrent adapt",
		log.Int("processes", processes), log.Int("resources", len(items)))

	mu := sync.Mutex{}

	var ch = make(chan T, 50)
	wg := sync.WaitGroup{}
	wg.Add(processes)

	var results []S

	for i := 0; i < processes; i++ {
		go func() {
			for {
				in, ok := <-ch
				if !ok {
					wg.Done()
					return
				}
				out, err := adapt(in, currentState)
				ctx.Tracker().IncrementResource()
				if err != nil {
					// TODO: use ErrorContext
					log.Error("Error to adapt resource", log.Any("resource", in), log.Err(err))
					continue
				}

				if out != nil {
					mu.Lock()
					results = append(results, *out)
					mu.Unlock()
				}
			}
		}()
	}

	for _, item := range items {
		ch <- item
	}

	close(ch)
	wg.Wait()

	return results
}
