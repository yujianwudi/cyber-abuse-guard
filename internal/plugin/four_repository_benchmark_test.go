package plugin

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard/internal/subject"
)

func BenchmarkFourRepositoryModelRoute(b *testing.B) {
	b.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	balancedConfig := "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
	subjectConfig := "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 64\n"

	shortChat, _ := fourRepoMarshalAndCheckBytes(b, fourRepoChatUser, fourRepoBenignUser, "")
	shortResponses, _ := fourRepoMarshalAndCheckBytes(b, fourRepoResponsesUser, fourRepoBenignUser, "")
	additionalWrapper := repositoryNeutralSizedText(b, 17166, fourRepoSurrogateProfiles[2].core)
	additionalTools, _ := fourRepoMarshalAndCheckBytes(
		b, fourRepoAdditionalNamespace, additionalWrapper, fourRepoBenignUser,
	)
	benignNearNeighbor := repositoryNeutralSizedText(b, 17166, fourRepoSurrogateProfiles[4].core)
	nearNeighbor, _ := fourRepoMarshalAndCheckBytes(b, fourRepoResponsesUser, benignNearNeighbor, "")

	benchmarks := []struct {
		name    string
		config  string
		format  string
		body    []byte
		headers http.Header
	}{
		{name: "off/chat-clean", config: "mode: off\n", format: "openai", body: shortChat},
		{name: "balanced/chat-clean", config: balancedConfig, format: "openai", body: shortChat},
		{name: "balanced/responses-clean", config: balancedConfig, format: "openai-response", body: shortResponses},
		{
			name: "balanced/chat-clean-subject-enabled", config: subjectConfig, format: "openai", body: shortChat,
			headers: http.Header{"Authorization": []string{"Bearer benchmark-clean-subject"}},
		},
		{name: "balanced/additional-tools-wrapper-17166B", config: balancedConfig, format: "openai-response", body: additionalTools},
		{name: "balanced/trusted-benign-neighbor-17166B", config: balancedConfig, format: "openai-response", body: nearNeighbor},
	}

	for _, benchmark := range benchmarks {
		benchmark := benchmark
		b.Run(benchmark.name, func(b *testing.B) {
			p := New()
			b.Cleanup(p.Shutdown)
			register(b, p, benchmark.config)

			request, err := json.Marshal(pluginapi.ModelRouteRequest{
				SourceFormat:   benchmark.format,
				RequestedModel: "four-repository-benchmark",
				Headers:        benchmark.headers,
				Body:           benchmark.body,
			})
			if err != nil {
				b.Fatal(err)
			}
			raw, code := p.Call(pluginabi.MethodModelRoute, request)
			if code != 0 {
				b.Fatalf("model.route code=%d envelope=%s", code, raw)
			}
			var route pluginapi.ModelRouteResponse
			decodeOKResult(b, raw, &route)
			if route.Handled {
				b.Fatalf("benign benchmark fixture was handled: %+v", route)
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(benchmark.body)))
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				raw, code = p.Call(pluginabi.MethodModelRoute, request)
				if code != 0 || len(raw) == 0 {
					b.Fatalf("model.route code=%d envelope=%s", code, raw)
				}
			}
		})
	}
}

func BenchmarkFourRepositoryParallelCleanSubjectEnabled(b *testing.B) {
	b.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	b.Cleanup(p.Shutdown)
	register(b, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 1024\n")
	body, _ := fourRepoMarshalAndCheckBytes(b, fourRepoChatUser, fourRepoBenignUser, "")
	request, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat:   "openai",
		RequestedModel: "four-repository-parallel-benchmark",
		Headers:        http.Header{"Authorization": []string{"Bearer benchmark-parallel-clean"}},
		Body:           body,
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			raw, code := p.Call(pluginabi.MethodModelRoute, request)
			if code != 0 || len(raw) == 0 {
				b.Errorf("model.route code=%d envelope=%s", code, raw)
				return
			}
		}
	})
}
