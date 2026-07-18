SHELL := /bin/bash

GO ?= go
GOFMT ?= gofmt
CC ?= cc
VERSION ?= 0.15
CYCLONEDX_GOMOD ?= cyclonedx-gomod
CYCLONEDX_GOMOD_VERSION ?= v1.9.0
GOVULNCHECK ?= govulncheck
GOVULNCHECK_VERSION ?= v1.6.0
PLUGIN_ID := cyber-abuse-guard
DIST_DIR := $(CURDIR)/dist
DIRTY_SUFFIX := $(if $(filter 1,$(ALLOW_DIRTY_BUILD)),-dirty,)
ARTIFACT_VERSION := $(VERSION)$(DIRTY_SUFFIX)
SO := $(DIST_DIR)/$(PLUGIN_ID)-v$(ARTIFACT_VERSION).so
STORE_ZIP := $(DIST_DIR)/$(PLUGIN_ID)_$(ARTIFACT_VERSION)_linux_amd64.zip
AUDIT_BUNDLE := $(DIST_DIR)/$(PLUGIN_ID)-v$(ARTIFACT_VERSION)-audit-bundle.zip
TEST_TAGS := sqlite_omit_load_extension
ROUND6_SAFE_PACKAGES := \
	./cmd/cyber-abuse-guard \
	./cmd/development-adversarial-v11-prep-validator \
	./cmd/development-public-jailbreak-patterns-v1-validator \
	./internal/audit \
	./internal/buildinfo \
	./internal/classifier \
	./internal/config \
	./internal/extract \
	./internal/fixturepublish \
	./internal/plugin \
	./internal/rules \
	./internal/subject \
	./rules
CPA_ROUTER_FIXTURE_SCENARIOS := guard-priority-higher fixture-priority-higher \
	equal-priority-aaa-router-before-guard equal-priority-zzz-router-after-guard \
	higher-priority-route-error-falls-through-to-guard \
	higher-priority-invalid-target-falls-through-to-guard \
	higher-priority-empty-identifier-falls-through-to-guard \
	higher-priority-no-formats-falls-through-to-guard \
	higher-priority-router-without-executor-falls-through-to-guard \
	higher-priority-oauth-scope-is-not-static-ready \
	higher-priority-unhandled-router-falls-through-to-guard \
	guard-not-loaded-fixture-handles guard-registration-failure-fixture-handles \
	guard-disabled-fixture-handles guard-not-loaded-unhandled-fixture-reaches-native-provider

.NOTPARALLEL: release round6-development-artifacts

.PHONY: all format-check round6-format-check git-diff-check round6-git-diff-check module-verify round6-module-verify test unit-test vet round6-vet race \
	fuzz-smoke script-test corpus-regression development-public-jailbreak-corpus consumed-boundary-test holdout-test benchmark round6-benchmark build-linux-amd64 \
	integration-compile integration-test cpa-host-blackbox cpa-router-fixture-blackbox cpa-host-fixture-contract cpa-latest-compat round4-regression round5-regression round6-regression round6-development-artifacts round6-reproducibility-test round6-script-test round6-cpa-store-contract management-proxy-413-test ruleset-manifest sbom vulncheck round6-vulncheck release-preflight \
	package-release package-source-release release release-evidence formal-release external-release-attestation frozen-evaluation-v10-tree release-doc-consistency release-doc-consistency-test verify-release verification-fault-test cpa-store-contract artifact-hash \
	reproducibility-test clean-tree-check tools clean

all: test build-linux-amd64

format-check:
	@command -v "$(GOFMT)" >/dev/null 2>&1 || { \
		echo 'required formatter not found: $(GOFMT)' >&2; exit 1; \
	}; \
	files=(); \
	while IFS= read -r -d '' file; do \
		[[ -f "$$file" ]] && files+=("$$file"); \
	done < <(git ls-files -co --exclude-standard -z -- '*.go'); \
	if [[ $${#files[@]} -eq 0 ]]; then exit 0; fi; \
	bad="$$($(GOFMT) -l "$${files[@]}")" || exit $$?; \
	if [[ -n "$$bad" ]]; then printf 'gofmt required:\n%s\n' "$$bad" >&2; exit 1; fi

round6-format-check:
	@command -v "$(GOFMT)" >/dev/null 2>&1 || { \
		echo 'required formatter not found: $(GOFMT)' >&2; exit 1; \
	}; \
	files=(); \
	while IFS= read -r -d '' file; do files+=("$$file"); done < <(./scripts/round6-safe-go-files.sh); \
	if [[ $${#files[@]} -eq 0 ]]; then echo 'Round6 safe Go file set is empty' >&2; exit 1; fi; \
	bad="$$($(GOFMT) -l "$${files[@]}")" || exit $$?; \
	if [[ -n "$$bad" ]]; then printf 'gofmt required:\n%s\n' "$$bad" >&2; exit 1; fi

git-diff-check:
	git diff --check

round6-git-diff-check:
	git diff --check -- . \
		':(exclude,glob,icase)cmd/**/*evaluation*' \
		':(exclude,glob,icase)cmd/**/*holdout*' \
		':(exclude,glob,icase)cmd/**/*consumed*' \
		':(exclude,glob,icase)cmd/**/*private*' \
		':(exclude,glob,icase)cmd/**/*blind*' \
		':(exclude,glob,icase)cmd/**/*retired*' \
		':(exclude,glob,icase)docs/**/*EVALUATION_*' \
		':(exclude,glob,icase)docs/**/*HOLDOUT_*' \
		':(exclude,glob,icase)docs/**/*HOLDOUT_REPORT.md' \
		':(exclude,glob,icase)docs/**/*consumed*' \
		':(exclude,glob,icase)docs/**/*private*' \
		':(exclude,glob,icase)docs/**/*blind*' \
		':(exclude,glob,icase)docs/**/*retired*' \
		':(exclude,glob,icase)internal/classifier/**/*evaluation*' \
		':(exclude,glob,icase)internal/classifier/**/*holdout*' \
		':(exclude,glob,icase)internal/classifier/**/*consumed*' \
		':(exclude,glob,icase)internal/classifier/**/*private*' \
		':(exclude,glob,icase)internal/classifier/**/*blind*' \
		':(exclude,glob,icase)internal/classifier/**/*retired*' \
		':(exclude,glob,icase)testdata/**/*evaluation*' \
		':(exclude,glob,icase)testdata/**/*holdout*' \
		':(exclude,glob,icase)testdata/**/*consumed*' \
		':(exclude,glob,icase)testdata/**/*private*' \
		':(exclude,glob,icase)testdata/**/*blind*' \
		':(exclude,glob,icase)testdata/**/*retired*'

module-verify:
	$(GO) mod verify
	$(GO) mod tidy -diff
	$(GO) -C integration/pluginstorecontract mod verify
	$(GO) -C integration/pluginstorecontract mod tidy -diff
	$(GO) -C integration/cpalatestcontract mod verify
	$(GO) -C integration/cpalatestcontract mod tidy -diff

round6-module-verify:
	$(GO) mod verify
	$(GO) list -tags=$(TEST_TAGS) -deps $(ROUND6_SAFE_PACKAGES) >/dev/null
	$(GO) -C integration/pluginstorecontract mod verify
	$(GO) -C integration/pluginstorecontract mod tidy -diff
	$(GO) -C integration/cpalatestcontract mod verify
	$(GO) -C integration/cpalatestcontract mod tidy -diff

test:
	GO=$(GO) TEST_TAGS=$(TEST_TAGS) bash ./scripts/go-safe-development-test.sh test

unit-test: test

vet:
	$(GO) vet -tags=$(TEST_TAGS) ./...

round6-vet:
	$(GO) vet -tags=$(TEST_TAGS) $(ROUND6_SAFE_PACKAGES)

race:
	GO=$(GO) TEST_TAGS=$(TEST_TAGS) bash ./scripts/go-safe-development-test.sh race

fuzz-smoke:
	$(GO) test ./internal/extract -run='^$$' -fuzz='^FuzzExtractText$$' -fuzztime=5s
	$(GO) test ./internal/extract -run='^$$' -fuzz='^FuzzExtractRequestMediaMemberOrder$$' -fuzztime=5s
	$(GO) test ./internal/extract -run='^$$' -fuzz='^FuzzExtractRequestScalarMediaCarrierPermutation$$' -fuzztime=5s
	$(GO) test ./internal/extract -run='^$$' -fuzz='^FuzzExtractRequestContentType$$' -fuzztime=5s
	$(GO) test ./internal/extract -run='^$$' -fuzz='^FuzzExtractRequestMultipart$$' -fuzztime=5s
	$(GO) test ./internal/extract -run='^$$' -fuzz='^FuzzExtractRequestMultipartUnknownFieldEvidenceOrder$$' -fuzztime=5s
	$(GO) test ./internal/extract -run='^$$' -fuzz='^FuzzRound6JSONStringChunkDecoderMatchesStdlib$$' -fuzztime=5s
	$(GO) test ./internal/classifier -run='^$$' -fuzz='^FuzzClassifier$$' -fuzztime=5s
	$(GO) test ./internal/classifier -run='^$$' -fuzz='^FuzzMetaOverrideClausePermutation$$' -fuzztime=5s
	$(GO) test ./internal/classifier -run='^$$' -fuzz='^FuzzMetaOverrideEncodingAndPartSplit$$' -fuzztime=5s
	$(GO) test ./internal/classifier -run='^$$' -fuzz='^FuzzDefensiveQuotedSampleBoundary$$' -fuzztime=5s
	$(GO) test ./internal/config -run='^$$' -fuzz='^FuzzConfigParser$$' -fuzztime=5s

script-test:
	bash -n ./scripts/go-safe-development-test.sh
	bash -n ./scripts/cpa-latest-compat.sh
	bash -n ./scripts/round6-candidate-artifacts.sh
	bash -n ./scripts/round6-rc-artifacts.sh
	./scripts/release-candidate-contract-test.sh
	bash -n ./scripts/verify-external-release-attestation.sh
	./scripts/verify-external-release-attestation-test.sh
	bash -n ./scripts/source-release-exclusion-contract-test.sh
	./scripts/source-release-exclusion-contract-test.sh
	bash -n ./scripts/verify-frozen-evaluation-v10-tree.sh
	./scripts/verify-frozen-evaluation-v10-tree.sh
	./scripts/check-production-health-test.sh
	GO=$(GO) ./scripts/create-store-archive-test.sh
	./scripts/generate-hmac-key-test.sh
	bash ./scripts/release-evidence-privacy-test.sh
	./scripts/release-doc-consistency-test.sh

round6-script-test:
	bash -n ./scripts/go-safe-development-test.sh
	bash -n ./scripts/cpa-latest-compat.sh
	bash -n ./scripts/round6-candidate-artifacts.sh
	bash -n ./scripts/round6-rc-artifacts.sh
	./scripts/release-candidate-contract-test.sh
	bash -n ./scripts/verify-external-release-attestation.sh
	./scripts/verify-external-release-attestation-test.sh
	bash -n ./scripts/source-release-exclusion-contract-test.sh
	./scripts/source-release-exclusion-contract-test.sh
	bash -n ./scripts/verify-frozen-evaluation-v10-tree.sh
	./scripts/verify-frozen-evaluation-v10-tree.sh
	bash -n ./scripts/round6-reproducibility-test.sh
	bash -n ./scripts/round6-safe-go-files.sh
	python3 -B ./scripts/round6_safe_gate_contract_test.py
	python3 -B ./scripts/round6_safe_gate_contract.py --root .
	./scripts/check-production-health-test.sh
	GO=$(GO) ./scripts/create-store-archive-test.sh
	./scripts/generate-hmac-key-test.sh
	bash ./scripts/release-evidence-privacy-test.sh
	bash ./scripts/round6-doc-consistency-fixture-test.sh

corpus-regression:
	$(GO) test -tags=$(TEST_TAGS) ./internal/classifier \
		-run='^TestBalancedCorpusMetrics$$' -count=1 -v

development-public-jailbreak-corpus:
	@listed="$$($(GO) test ./cmd/development-public-jailbreak-patterns-v1-validator -list='^(TestDevelopmentPublicJailbreakPatternsV1Corpus|TestDevelopmentPublicJailbreakPatternsRejectsLiveMaterial|TestDevelopmentPublicJailbreakPatternsRejectsManifestCoverageDrift|TestDevelopmentPublicJailbreakPatternsRejectsDirectoryDrift|TestDevelopmentPublicJailbreakPatternsRejectsSymlink)$$')" || exit $$?; \
	for test_name in \
		TestDevelopmentPublicJailbreakPatternsV1Corpus \
		TestDevelopmentPublicJailbreakPatternsRejectsLiveMaterial \
		TestDevelopmentPublicJailbreakPatternsRejectsManifestCoverageDrift \
		TestDevelopmentPublicJailbreakPatternsRejectsDirectoryDrift \
		TestDevelopmentPublicJailbreakPatternsRejectsSymlink; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { \
			echo "required development public-jailbreak validator $$test_name is missing" >&2; exit 1; \
		}; \
	done
	$(GO) test ./cmd/development-public-jailbreak-patterns-v1-validator \
		-run='^(TestDevelopmentPublicJailbreakPatternsV1Corpus|TestDevelopmentPublicJailbreakPatternsRejectsLiveMaterial|TestDevelopmentPublicJailbreakPatternsRejectsManifestCoverageDrift|TestDevelopmentPublicJailbreakPatternsRejectsDirectoryDrift|TestDevelopmentPublicJailbreakPatternsRejectsSymlink)$$' -count=1 -v

consumed-boundary-test:
	GO=$(GO) TEST_TAGS=$(TEST_TAGS) bash ./scripts/go-safe-development-test.sh boundary

holdout-test:
	@echo 'evaluation-v10 is frozen CONSUMED/FAIL historical evidence and must not be rerun' >&2
	@exit 1

benchmark:
	$(GO) test ./internal/classifier \
		-run='^(TestClassifier(Adversarial)?PerformanceAcceptance|TestRound5MetaOverridePerformanceAcceptance|TestRound5AdjacentNegationCandidateFloodPerformanceAcceptance)$$' -count=1 -v
	$(GO) test ./internal/classifier -run='^$$' -bench=. -benchmem -count=3
	$(GO) test ./internal/extract -run='^$$' \
		-bench='^(BenchmarkExtractRequest(ReverseOrderedMedia|Multipart|ScalarCarrierPermutation).*|BenchmarkMultipartUnknownFileField(1MiB|8MiB))$$' \
		-benchmem -benchtime=3x

round6-benchmark: benchmark
	@$(GO) test ./internal/extract -list='^BenchmarkRound6ScanLongJSON$$' | \
		grep -Fxq 'BenchmarkRound6ScanLongJSON' || { \
			echo 'required Round6 long-JSON benchmark is missing' >&2; exit 1; \
		}
	$(GO) test ./internal/extract -run='^$$' \
		-bench='^BenchmarkRound6ScanLongJSON$$' -benchmem -benchtime=1x -count=1

round4-regression:
	@listed="$$($(GO) test ./internal/extract ./internal/plugin -list='^(TestExtractRequestMediaObjectMemberOrderInvariant|TestExtractRequestMultipartUnknownFieldIsIncompleteAndPrivate|TestBalancedMultipartUnknownFieldAllowsWithoutClassification|TestStrictMultipartUnknownFieldBlocksWithoutClassification)$$')" || exit $$?; \
	for test_name in TestExtractRequestMediaObjectMemberOrderInvariant TestExtractRequestMultipartUnknownFieldIsIncompleteAndPrivate TestBalancedMultipartUnknownFieldAllowsWithoutClassification TestStrictMultipartUnknownFieldBlocksWithoutClassification; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { echo "required round-four regression $$test_name is missing" >&2; exit 1; }; \
	done
	$(GO) test ./internal/extract -count=1 -v \
		-run='^(TestExtractRequestMediaObjectMemberOrderInvariant|TestExtractRequestMultipartUnknownFieldIsIncompleteAndPrivate)$$'
	$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v \
		-run='^(TestBalancedMultipartUnknownFieldAllowsWithoutClassification|TestStrictMultipartUnknownFieldBlocksWithoutClassification)$$'

round5-regression:
	@listed="$$($(GO) test ./internal/extract -list='^(TestExtractRequestScalarMediaCarrierMemberOrderInvariant|TestExtractRequestConflictingMediaMarkersAreOrderInvariant|TestExtractRequestInheritedMediaKindUsesChildExplicitMarker|TestExtractRequestScalarMediaCarrierNeverEntersPartsOrSegments|TestExtractRequestScalarMediaCarrierDoesNotConsumeTextBudget|TestExtractRequestScalarMediaCarrierBareBinaryBase64FailsClosed|TestExtractRequestScalarMediaCarrierMalformedMixedCaseDataURLFailsClosed|TestExtractRequestNonMediaSourceURIFallsBackToText|TestExtractRequestToolSourceURIRemainsInspectable|TestExtractRequestScalarCarrierDoesNotCrossSiblingOrToolBoundary|TestExtractRequestScalarCarrierAllowedChildParentResolution|TestExtractRequestScalarCarrierOverflowDisposition|TestExtractRequestToolScalarCarrierLongTextIsInspectable|TestExtractRequestScalarCarrierPerformanceAcceptance|TestExtractRequestMultipartUnknownFileFieldIsSchemaIncomplete|TestExtractRequestMultipartUnknownFieldPrecedesFileEvidence|TestExtractRequestMultipartUnnamedAttachmentIsSchemaIncomplete|TestExtractRequestMultipartUnknownFileAllocationsDoNotScaleWithPayload|TestToolSchemaKnownBooleanControlIsMapped|TestToolSchemaUnknownControlKeyIsIncomplete|TestToolSchemaMemberOrderInvariant|TestOrdinaryBusinessJSONKeysDoNotBecomePromptText|TestRound5LargeTopLevelToolDefinitionsRemainInspectableWithoutRoleIndex|TestProviderSafetyFieldsRequireHostSchemaPolicy|TestExtractTextToolTransactionSharesPartBudget|TestExtractRawPartsToolTransactionSharesPartBudget)$$')" || exit $$?; \
	for test_name in \
		TestExtractRequestScalarMediaCarrierMemberOrderInvariant \
		TestExtractRequestConflictingMediaMarkersAreOrderInvariant \
		TestExtractRequestInheritedMediaKindUsesChildExplicitMarker \
		TestExtractRequestScalarMediaCarrierNeverEntersPartsOrSegments \
		TestExtractRequestScalarMediaCarrierDoesNotConsumeTextBudget \
		TestExtractRequestScalarMediaCarrierBareBinaryBase64FailsClosed \
		TestExtractRequestScalarMediaCarrierMalformedMixedCaseDataURLFailsClosed \
		TestExtractRequestNonMediaSourceURIFallsBackToText \
		TestExtractRequestToolSourceURIRemainsInspectable \
		TestExtractRequestScalarCarrierDoesNotCrossSiblingOrToolBoundary \
		TestExtractRequestScalarCarrierAllowedChildParentResolution \
		TestExtractRequestScalarCarrierOverflowDisposition \
		TestExtractRequestToolScalarCarrierLongTextIsInspectable \
		TestExtractRequestScalarCarrierPerformanceAcceptance \
		TestExtractRequestMultipartUnknownFileFieldIsSchemaIncomplete \
		TestExtractRequestMultipartUnknownFieldPrecedesFileEvidence \
		TestExtractRequestMultipartUnnamedAttachmentIsSchemaIncomplete \
		TestExtractRequestMultipartUnknownFileAllocationsDoNotScaleWithPayload \
		TestToolSchemaKnownBooleanControlIsMapped \
		TestToolSchemaUnknownControlKeyIsIncomplete \
		TestToolSchemaMemberOrderInvariant \
		TestOrdinaryBusinessJSONKeysDoNotBecomePromptText \
		TestRound5LargeTopLevelToolDefinitionsRemainInspectableWithoutRoleIndex \
		TestProviderSafetyFieldsRequireHostSchemaPolicy \
		TestExtractTextToolTransactionSharesPartBudget \
		TestExtractRawPartsToolTransactionSharesPartBudget; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { echo "required round-five extract regression $$test_name is missing" >&2; exit 1; }; \
	done
	@listed="$$($(GO) test ./internal/classifier -list='^(TestRound5MetaOverrideFamiliesProduceFixedEvidence|TestRound5MetaOverridePerformanceAcceptance|TestMetaOverrideClauseBudgetPerformance|TestMetaOverrideClauseBudgetRejectsDefensiveCredit|TestRound5PersistentInstructionInjectionBlocksOnlyActiveSafetyOverride|TestRound5PersistentInstructionInjectionAcrossLinkedUserSegments|TestRound5PersistentBlockSurvivesIncidentalLowScoreTaxonomyTerms|TestRound5WrapperAuditSurvivesIncidentalLowScoreTaxonomyTerms|TestRound5MetaOverrideBenignNearNeighborsAllow|TestRound5MetaOverrideDefensiveQuotedSamplesRemainInert|TestRound5MetaOverrideDefensiveTailCannotAuthorizeExecution|TestRound5MalformedUTF8DirectiveBoundariesConsumeDecodedWidth|TestRound5UnrelatedPassiveNegationCannotLaunderMetaTarget|TestRound5MetaOverrideBilingualFamilies|TestRound5RefusalScopeOutputAndCompoundIntentHardening|TestRound5AgenticEscalationAmplifiesButDoesNotReplaceBaseTaxonomy|TestRound5AdjacentCompactIntentNegationFailsClosed|TestRound5AdjacentPartsNegationReversalCannotHideAbuse|TestRound5AdjacentUserSegmentsNegationReversalCannotHideAbuse|TestRound5AdjacentNegationCandidateFloodFailsClosed|TestRound5AdjacentNegationCandidateFloodPerformanceAcceptance|TestRound5AdjacentOverflowPreservesAllMatchedCores|TestRound5AdjacentPartsNegationReversalSurvivesTrailingParts|TestRound5AdjacentReversalUsesConfiguredHardBlockThreshold|TestRound5NegationReversalKeepsTrueProhibitionsBenign|TestRound5NormalizedContractionsRemainNegationReversals|TestRound5CoordinatedCrossCategoryProhibitionsRemainBenign|TestRound5CrossCategoryNegationDoesNotCoverOperationalTail|TestRound5DirectiveBoundaryRunsPreserveSentenceBreaks|TestRound5EarlierLiteralNegationCannotHideLaterCompactClause|TestRound5LargeAdjacentNegationReconstructionFailsClosed|TestRound5LongNegationReversalBridgeFailsActive|TestRound5NegatedProhibitionModalBridgeFailsActive|TestRound5RepeatedIntentYInflectionsFailActive|TestRound5NegationCannotHideLaterActiveIntent|TestRound5UnrelatedSignalsDoNotPolluteMetaTail|TestRoleAwareTruncatedDefensiveReconstructionKeepsWrapperFinding)$$')" || exit $$?; \
	for test_name in \
		TestRound5MetaOverrideFamiliesProduceFixedEvidence \
		TestRound5MetaOverridePerformanceAcceptance \
		TestMetaOverrideClauseBudgetPerformance \
		TestMetaOverrideClauseBudgetRejectsDefensiveCredit \
		TestRound5PersistentInstructionInjectionBlocksOnlyActiveSafetyOverride \
		TestRound5PersistentInstructionInjectionAcrossLinkedUserSegments \
		TestRound5PersistentBlockSurvivesIncidentalLowScoreTaxonomyTerms \
		TestRound5WrapperAuditSurvivesIncidentalLowScoreTaxonomyTerms \
		TestRound5MetaOverrideBenignNearNeighborsAllow \
		TestRound5MetaOverrideDefensiveQuotedSamplesRemainInert \
		TestRound5MetaOverrideDefensiveTailCannotAuthorizeExecution \
		TestRound5MalformedUTF8DirectiveBoundariesConsumeDecodedWidth \
		TestRound5MetaOverrideBilingualFamilies \
		TestRound5RefusalScopeOutputAndCompoundIntentHardening \
		TestRound5AgenticEscalationAmplifiesButDoesNotReplaceBaseTaxonomy \
		TestRound5AdjacentCompactIntentNegationFailsClosed \
		TestRound5AdjacentPartsNegationReversalCannotHideAbuse \
		TestRound5AdjacentUserSegmentsNegationReversalCannotHideAbuse \
		TestRound5AdjacentNegationCandidateFloodFailsClosed \
		TestRound5AdjacentNegationCandidateFloodPerformanceAcceptance \
		TestRound5AdjacentOverflowPreservesAllMatchedCores \
		TestRound5AdjacentPartsNegationReversalSurvivesTrailingParts \
		TestRound5AdjacentReversalUsesConfiguredHardBlockThreshold \
		TestRound5NegationReversalKeepsTrueProhibitionsBenign \
		TestRound5NormalizedContractionsRemainNegationReversals \
		TestRound5CoordinatedCrossCategoryProhibitionsRemainBenign \
		TestRound5CrossCategoryNegationDoesNotCoverOperationalTail \
		TestRound5DirectiveBoundaryRunsPreserveSentenceBreaks \
		TestRound5EarlierLiteralNegationCannotHideLaterCompactClause \
		TestRound5LargeAdjacentNegationReconstructionFailsClosed \
		TestRound5LongNegationReversalBridgeFailsActive \
		TestRound5NegatedProhibitionModalBridgeFailsActive \
		TestRound5RepeatedIntentYInflectionsFailActive \
		TestRound5NegationCannotHideLaterActiveIntent \
		TestRound5UnrelatedPassiveNegationCannotLaunderMetaTarget \
		TestRound5UnrelatedSignalsDoNotPolluteMetaTail \
		TestRoleAwareTruncatedDefensiveReconstructionKeepsWrapperFinding; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { echo "required round-five classifier regression $$test_name is missing" >&2; exit 1; }; \
	done
	@listed="$$($(GO) test -tags=$(TEST_TAGS) ./internal/plugin -list='^(TestBalancedMultipartUnknownFileFieldAllowsAndAuditsWithoutClassification|TestStrictMultipartUnknownFileFieldBlocksEvenWhenOpaquePolicyAllows|TestMultipartUnknownFileFieldAuditIsFixedAndPrivate|TestControlPlaneMetaOverrideCounterIsFixedAndOrthogonal|TestIncompleteRequestDoesNotEmitControlPlaneCounter|TestWrapperOnlyControlPlaneDoesNotAccumulateSubjectRisk|TestPersistentControlPlaneBlockRemainsCategoryFreeAndDoesNotPersistSubjectRisk|TestOpaqueMediaBlockCannotBeDowngradedByWrapperAudit|TestCompleteClassifierBlockStillWinsOverOpaqueMediaBlock|TestToolSchemaMappedControlIsAuditedAndCounted|TestToolSchemaUnknownControlIsIncompleteWithoutClassification|TestStrictToolSchemaUnknownControlBlocksWithoutClassification|TestAdjacentNegationProofBudgetBlocksBalancedWithoutIncompleteDowngrade|TestLargeTopLevelToolDefinitionCannotBypassBalanced|TestRegistrationMatchesTargetCPAContract|TestRouterUsesRoleAwareConversationClassification)$$')" || exit $$?; \
	for test_name in \
		TestBalancedMultipartUnknownFileFieldAllowsAndAuditsWithoutClassification \
		TestStrictMultipartUnknownFileFieldBlocksEvenWhenOpaquePolicyAllows \
		TestMultipartUnknownFileFieldAuditIsFixedAndPrivate \
		TestControlPlaneMetaOverrideCounterIsFixedAndOrthogonal \
		TestIncompleteRequestDoesNotEmitControlPlaneCounter \
		TestWrapperOnlyControlPlaneDoesNotAccumulateSubjectRisk \
		TestPersistentControlPlaneBlockRemainsCategoryFreeAndDoesNotPersistSubjectRisk \
		TestOpaqueMediaBlockCannotBeDowngradedByWrapperAudit \
		TestCompleteClassifierBlockStillWinsOverOpaqueMediaBlock \
		TestToolSchemaMappedControlIsAuditedAndCounted \
		TestToolSchemaUnknownControlIsIncompleteWithoutClassification \
		TestStrictToolSchemaUnknownControlBlocksWithoutClassification \
		TestAdjacentNegationProofBudgetBlocksBalancedWithoutIncompleteDowngrade \
		TestLargeTopLevelToolDefinitionCannotBypassBalanced \
		TestRegistrationMatchesTargetCPAContract \
		TestRouterUsesRoleAwareConversationClassification; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { echo "required round-five plugin regression $$test_name is missing" >&2; exit 1; }; \
	done
	$(GO) test ./internal/extract -count=1 -v \
		-run='^(TestExtractRequestScalarMediaCarrierMemberOrderInvariant|TestExtractRequestConflictingMediaMarkersAreOrderInvariant|TestExtractRequestInheritedMediaKindUsesChildExplicitMarker|TestExtractRequestScalarMediaCarrierNeverEntersPartsOrSegments|TestExtractRequestScalarMediaCarrierDoesNotConsumeTextBudget|TestExtractRequestScalarMediaCarrierBareBinaryBase64FailsClosed|TestExtractRequestScalarMediaCarrierMalformedMixedCaseDataURLFailsClosed|TestExtractRequestNonMediaSourceURIFallsBackToText|TestExtractRequestToolSourceURIRemainsInspectable|TestExtractRequestScalarCarrierDoesNotCrossSiblingOrToolBoundary|TestExtractRequestScalarCarrierAllowedChildParentResolution|TestExtractRequestScalarCarrierOverflowDisposition|TestExtractRequestToolScalarCarrierLongTextIsInspectable|TestExtractRequestScalarCarrierPerformanceAcceptance|TestExtractRequestMultipartUnknownFileFieldIsSchemaIncomplete|TestExtractRequestMultipartUnknownFieldPrecedesFileEvidence|TestExtractRequestMultipartUnnamedAttachmentIsSchemaIncomplete|TestExtractRequestMultipartUnknownFileAllocationsDoNotScaleWithPayload|TestToolSchemaKnownBooleanControlIsMapped|TestToolSchemaUnknownControlKeyIsIncomplete|TestToolSchemaMemberOrderInvariant|TestOrdinaryBusinessJSONKeysDoNotBecomePromptText|TestRound5LargeTopLevelToolDefinitionsRemainInspectableWithoutRoleIndex|TestProviderSafetyFieldsRequireHostSchemaPolicy|TestExtractTextToolTransactionSharesPartBudget|TestExtractRawPartsToolTransactionSharesPartBudget)$$'
	$(GO) test ./internal/classifier -count=1 -v \
		-run='^(TestRound5MetaOverrideFamiliesProduceFixedEvidence|TestRound5MetaOverridePerformanceAcceptance|TestMetaOverrideClauseBudgetPerformance|TestMetaOverrideClauseBudgetRejectsDefensiveCredit|TestRound5PersistentInstructionInjectionBlocksOnlyActiveSafetyOverride|TestRound5PersistentInstructionInjectionAcrossLinkedUserSegments|TestRound5PersistentBlockSurvivesIncidentalLowScoreTaxonomyTerms|TestRound5WrapperAuditSurvivesIncidentalLowScoreTaxonomyTerms|TestRound5MetaOverrideBenignNearNeighborsAllow|TestRound5MetaOverrideDefensiveQuotedSamplesRemainInert|TestRound5MetaOverrideDefensiveTailCannotAuthorizeExecution|TestRound5MalformedUTF8DirectiveBoundariesConsumeDecodedWidth|TestRound5UnrelatedPassiveNegationCannotLaunderMetaTarget|TestRound5MetaOverrideBilingualFamilies|TestRound5RefusalScopeOutputAndCompoundIntentHardening|TestRound5AgenticEscalationAmplifiesButDoesNotReplaceBaseTaxonomy|TestRound5AdjacentCompactIntentNegationFailsClosed|TestRound5AdjacentPartsNegationReversalCannotHideAbuse|TestRound5AdjacentUserSegmentsNegationReversalCannotHideAbuse|TestRound5AdjacentNegationCandidateFloodFailsClosed|TestRound5AdjacentNegationCandidateFloodPerformanceAcceptance|TestRound5AdjacentOverflowPreservesAllMatchedCores|TestRound5AdjacentPartsNegationReversalSurvivesTrailingParts|TestRound5AdjacentReversalUsesConfiguredHardBlockThreshold|TestRound5NegationReversalKeepsTrueProhibitionsBenign|TestRound5NormalizedContractionsRemainNegationReversals|TestRound5CoordinatedCrossCategoryProhibitionsRemainBenign|TestRound5CrossCategoryNegationDoesNotCoverOperationalTail|TestRound5DirectiveBoundaryRunsPreserveSentenceBreaks|TestRound5EarlierLiteralNegationCannotHideLaterCompactClause|TestRound5LargeAdjacentNegationReconstructionFailsClosed|TestRound5LongNegationReversalBridgeFailsActive|TestRound5NegatedProhibitionModalBridgeFailsActive|TestRound5RepeatedIntentYInflectionsFailActive|TestRound5NegationCannotHideLaterActiveIntent|TestRound5UnrelatedSignalsDoNotPolluteMetaTail|TestRoleAwareTruncatedDefensiveReconstructionKeepsWrapperFinding)$$'
	$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v \
		-run='^(TestBalancedMultipartUnknownFileFieldAllowsAndAuditsWithoutClassification|TestStrictMultipartUnknownFileFieldBlocksEvenWhenOpaquePolicyAllows|TestMultipartUnknownFileFieldAuditIsFixedAndPrivate|TestControlPlaneMetaOverrideCounterIsFixedAndOrthogonal|TestIncompleteRequestDoesNotEmitControlPlaneCounter|TestWrapperOnlyControlPlaneDoesNotAccumulateSubjectRisk|TestPersistentControlPlaneBlockRemainsCategoryFreeAndDoesNotPersistSubjectRisk|TestOpaqueMediaBlockCannotBeDowngradedByWrapperAudit|TestCompleteClassifierBlockStillWinsOverOpaqueMediaBlock|TestToolSchemaMappedControlIsAuditedAndCounted|TestToolSchemaUnknownControlIsIncompleteWithoutClassification|TestStrictToolSchemaUnknownControlBlocksWithoutClassification|TestAdjacentNegationProofBudgetBlocksBalancedWithoutIncompleteDowngrade|TestLargeTopLevelToolDefinitionCannotBypassBalanced|TestRegistrationMatchesTargetCPAContract|TestRouterUsesRoleAwareConversationClassification)$$'

round6-regression:
	@required=( \
		TestRound6ScanLongJSONFieldComplete \
		TestRound6ScanSixtyFiveRoleMessagesRemainComplete \
		TestRound6OneLogicalFieldMayUseFiveHundredThirteenChunks \
		TestRound6ExactChunkBoundariesRemainComplete \
		TestRound6FiveHundredThirteenLogicalFieldsAreIncomplete \
		TestRound6ClassificationChunkLimitIsCoverageIncomplete \
		TestRound6ClassificationChunkLimitUsesActualUTF8Chunks \
		TestRound6UnicodeEscapesAndSurrogatesReplayExactly \
		TestRound6MetadataPaddingDoesNotConsumeTextCoverage \
		TestRound6FutureNonMetadataEnvelopeRemainsInspectable \
		TestRound6LongOrdinaryPercentAndAmpersandRemainComplete \
		TestRound6MarkerLastMediaRemainsTransactional \
		TestRound6MediaLookingPrefixInOrdinaryTextRemainsInspectable \
		TestRound6AmbiguousRoleAbortsBeforeSinkConsumption \
		TestRound6StreamingRestoresBoundedEncodedTextViews \
		TestRound6OversizedPrintableBase64IsIncomplete \
		TestRound6OversizedBase64BinaryPrefixWithLatePrintableCanaryIsIncomplete \
		TestRound6OversizedBase64HighTextDensityWithControlSeparatorsIsIncomplete \
		TestRound6OversizedLowDiversityRawBase64TextIsIncomplete \
		TestRound6OversizedLowDiversityRawBase64ExtraAlphabetQuantumIsIncomplete \
		TestRound6OversizedLowDiversityBase64TrailingJunkIsIncomplete \
		TestRound6OversizedPrintableBase64WithTrailingJunkIsIncomplete \
		TestRound6OversizedBase64CharactersAfterPaddingAreIncomplete \
		TestRound6OversizedBase64ThirdPaddingIsIncomplete \
		TestRound6OversizedBase64BinaryPrefixLateTextAndTrailingJunkIsIncomplete \
		TestRound6OversizedBase64SecondPaddingWithInvalidQuantumIsIncomplete \
		TestRound6OversizedRawBase64ExtraAlphabetQuantumIsIncomplete \
		TestRound6OversizedRawBase64InvalidFirstPaddingIsIncomplete \
		TestRound6OversizedBase64BinaryPrefixLateTextAndEOFPaddingIsIncomplete \
		TestRound6OversizedBase64AlphabetProseRemainsComplete \
		TestRound6OversizedValidPercentEnvelopeIsIncomplete \
		TestRound6MultipartLongPromptStreamsWhileFileStaysOpaque \
		TestRound6MultipartZeroPartEOFFailsClosed \
		TestRound6MultipartPromptEmitsBoundedDecodedView \
		TestRound6MultipartExactChunkMultiplesAlwaysEndField \
		TestRound6TransformedMultipartJSONLongPromptStreamsCompletely \
		TestRound6TrueIncompleteAbortsSink \
		TestRound6TotalTextBudgetIsCoverageNotEnvelope \
		TestRound6TransactionalSelectionPreservesSourceFieldOrder \
		TestRound6UnknownAndProvenUserRolesRemainDistinct \
		TestRound6StreamingAllocationCountDoesNotScaleWithLongField \
	); \
	pattern="$$(IFS='|'; echo "$${required[*]}")"; \
	listed="$$($(GO) test ./internal/extract -list="^($$pattern)$$")" || exit $$?; \
	for test_name in "$${required[@]}"; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { \
			echo "required round-six extract regression $$test_name is missing" >&2; exit 1; \
		}; \
	done; \
	$(GO) test ./internal/extract -count=1 -v -run="^($$pattern)$$"
	@required=( \
		TestRound6StreamingCrossWindowLiteralAndNFKC \
		TestRound6SingleWindowHasNoBoundaryReconstruction \
		TestRound6StreamingPreservesShortRoleAwareDecisions \
		TestRound6RequiredChunkOverlapFitsConfigurationBudget \
		TestRound6StreamingNegationAcrossWindowRemainsInert \
		TestRound6StreamingLongAssistantQuotedRefusalRemainsInert \
		TestRound6StreamingUnclosedSafetyQuoteCommitsProvisionalFinding \
		TestRound6StreamingClosedSafetyQuoteDiscardsProvisionalFinding \
		TestRound6StreamingMappedToolControlRemainsAuditOnly \
		TestRound6StreamingControlPairDoesNotCarryBaseBehaviorAcrossRoles \
		TestRound6StreamingCompactMatcherSurvivesMoreThanOverlapSeparators \
		TestRound6StreamingDoesNotJoinDifferentRoleFields \
		TestRound6StreamingProcessesAllSixtyFiveFields \
		TestRound6DefaultBudgetCoversMaximumLogicalFieldFragmentation \
		TestRound6HardLogicalFieldBoundHasCompleteBudget \
		TestRound6StreamingInternalChunksDoNotConsumeLogicalPartBudget \
		TestRound6StreamingCoverageReasonsAreSeparateFromProofBudgets \
		TestRound6IncompleteClearsUnverifiedFinding \
		TestRound6StreamingPreservesThreeTurnRoleSemanticsAfterSixtyFourFields \
		TestRound6StreamingPreservesBoundedRoleCompositionsAfterSixtyFourFields \
		TestRound6StreamingQuotedSafetyPrefixDoesNotLaunderEarlierInstruction \
		TestRound6StreamingPriorSafetyWindowDoesNotLaunderLaterInstruction \
		TestRound6StreamingSplitSyntheticCoreBecomesIncomplete \
		TestRound6StreamingSplitSyntheticQualifiersBecomeIncomplete \
		TestRound6StreamingStrictSplitSyntheticCoreBecomesIncomplete \
		TestRound6StreamingStrictSplitWrapperOnlyMetaRemainsComplete \
		TestRound6StreamingNegatedSyntheticIntentRemainsComplete \
		TestRound6StreamingSyntheticFactsStayInsideLogicalField \
		TestRound6StreamingSyntheticSafetyQuoteTransactions \
		TestRound6StreamingLateHarmConflictBecomesIncomplete \
		TestRound6StreamingUnrelatedMetaWindowsDoNotCompose \
		TestRound6StreamingLateUnnegatedSyntheticIntentBecomesIncomplete \
		TestRound6StreamingUnclosedSafetyQuoteHarmConflictBecomesIncomplete \
		TestRound6StreamingLongPriorUserCoreAndFollowUpBecomesIncomplete \
		TestRound6StreamingLongAssistantTailDoesNotComposeBaseBehaviorWithUser \
		TestRound6StreamingClosedSafetyQuoteTailStaysInertAcrossNextUserField \
		TestRound6StreamingUnquotedTailAfterSafetyQuoteLinksNextUserField \
		TestRound6StreamingInvalidOrderIsOperationalError \
		TestRound6StreamingUntrustedFallbackPreservesAdjacentProofBudget \
		TestRound6StreamingUntrustedOverSixtyFourRetainsEarlyAndLateProofs \
	); \
	pattern="$$(IFS='|'; echo "$${required[*]}")"; \
	listed="$$($(GO) test ./internal/classifier -list="^($$pattern)$$")" || exit $$?; \
	for test_name in "$${required[@]}"; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { \
			echo "required round-six classifier regression $$test_name is missing" >&2; exit 1; \
		}; \
	done; \
	$(GO) test ./internal/classifier -count=1 -v -run="^($$pattern)$$"
	@required=( \
		TestInspectionDispositionIncompleteOverridesMaliciousPrefix \
		TestInspectionDispositionCompleteMaliciousTextStillBlocksBalanced \
		TestInspectionDispositionCompleteOpaqueMediaAuditDoesNotHideTextBlock \
		TestRound6LongText270KiBRolePositionMatrixBlocks \
		TestRound6LongTextOneMiBPositionMatrixBlocks \
		TestRound6CrossWindowCredentialCanaryBlocks \
		TestRound6CrossWindowNegationAndBenignRemainAllowed \
		TestRound6MetadataPaddingBeforeAndAfterDoesNotCreateScanLimit \
		TestRound6LongStreamingRequestBlocksDuringPreRoute \
		TestRound6LongProviderProfilesBlock \
		TestRound6LongMultipartPromptSafeAndMalicious \
		TestRound6TransformedMultipartJSONLongPromptMatrix \
	); \
	pattern="$$(IFS='|'; echo "$${required[*]}")"; \
	listed="$$($(GO) test -tags=$(TEST_TAGS) ./internal/plugin -list="^($$pattern)$$")" || exit $$?; \
	for test_name in "$${required[@]}"; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { \
			echo "required round-six plugin regression $$test_name is missing" >&2; exit 1; \
		}; \
	done; \
	$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v -run="^($$pattern)$$"
	@required=( \
		TestRound6ManagementTestUsesStreamingCoverageBeyondLegacyMaxScan \
		TestRound6ManagementTestReportsTrueIncompleteByMode \
		TestRound6StatusExposesEffectiveLimitsAndDisabledVerifiedFinding \
	); \
	pattern="$$(IFS='|'; echo "$${required[*]}")"; \
	listed="$$($(GO) test -tags=$(TEST_TAGS) ./internal/plugin -list="^($$pattern)$$")" || exit $$?; \
	for test_name in "$${required[@]}"; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { \
			echo "required round-six management regression $$test_name is missing" >&2; exit 1; \
		}; \
	done; \
	$(GO) test -tags=$(TEST_TAGS) ./internal/plugin -count=1 -v -run="^($$pattern)$$"
	@listed="$$($(GO) test ./internal/config -list='^TestRound6StreamingLimitMigration$$')" || exit $$?; \
	printf '%s\n' "$$listed" | grep -Fxq 'TestRound6StreamingLimitMigration' || { \
		echo 'required round-six configuration migration regression is missing' >&2; exit 1; \
	}; \
	$(GO) test ./internal/config -count=1 -v -run='^TestRound6StreamingLimitMigration$$'

round6-development-artifacts: build-linux-amd64 sbom
	@epoch="$$(git log -1 --format=%ct)"; \
	PLUGIN_BINARY="$(SO)" STORE_ARCHIVE="$(STORE_ZIP)" SOURCE_DATE_EPOCH="$$epoch" \
		./scripts/create-store-archive.sh
	@cd "$(DIST_DIR)" && sha256sum \
		"$(notdir $(SO))" \
		"$(notdir $(SO)).sha256" \
		"$(notdir $(STORE_ZIP))" \
		build-metadata.json \
		ruleset-manifest.json \
		ruleset.sha256 \
		sbom.cdx.json > checksums.txt
	@cd "$(DIST_DIR)" && sha256sum -c checksums.txt && sha256sum -c ruleset.sha256

round6-reproducibility-test:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) \
		./scripts/round6-reproducibility-test.sh

build-linux-amd64:
	GO=$(GO) VERSION=$(VERSION) ./scripts/build-linux-amd64.sh

integration-compile:
	$(GO) test -tags=integration,$(TEST_TAGS) -run='^$$' ./integration

integration-test: cpa-host-blackbox cpa-router-fixture-blackbox

cpa-host-blackbox: build-linux-amd64
	@listed="$$($(GO) test -tags=integration,$(TEST_TAGS) -list='^TestCPAPluginHostBlocksBeforeUpstream$$' ./integration)" || exit $$?; \
	printf '%s\n' "$$listed" | grep -Fxq 'TestCPAPluginHostBlocksBeforeUpstream' || { \
		echo 'required Host blackbox test TestCPAPluginHostBlocksBeforeUpstream is missing' >&2; exit 1; \
	}
	@work="$$(mktemp -d)"; trap 'rm -rf -- "$$work"' EXIT; \
	epoch="$$(git log -1 --format=%ct)"; \
	archive="$$work/$(notdir $(STORE_ZIP))"; \
	PLUGIN_BINARY="$(SO)" STORE_ARCHIVE="$$archive" SOURCE_DATE_EPOCH="$$epoch" \
		./scripts/create-store-archive.sh; \
	echo 'Host blackbox: InstallManifest archive and Host load use the exact standalone $(SO) identity'; \
	CYBER_ABUSE_GUARD_PLUGIN="$(SO)" \
	CYBER_ABUSE_GUARD_STORE_ARCHIVE="$$archive" \
	CYBER_ABUSE_GUARD_BUILD_METADATA="$(DIST_DIR)/build-metadata.json" \
	CYBER_ABUSE_GUARD_VERSION="$(ARTIFACT_VERSION)" \
	CYBER_ABUSE_GUARD_REQUIRE_STORE_INSTALL=1 \
	CYBER_ABUSE_GUARD_REQUIRE_HOST_INTEGRATION=1 \
	CGO_ENABLED=1 $(GO) test -tags=integration,$(TEST_TAGS) -v -count=1 \
		-run='^TestCPAPluginHostBlocksBeforeUpstream$$' ./integration

cpa-router-fixture-blackbox: build-linux-amd64
	@listed="$$($(GO) test -tags=integration,$(TEST_TAGS) -list='^TestCPAPluginHostRouterFixtureMatrix$$' ./integration)" || exit $$?; \
	printf '%s\n' "$$listed" | grep -Fxq 'TestCPAPluginHostRouterFixtureMatrix' || { \
		echo 'required Router blackbox test TestCPAPluginHostRouterFixtureMatrix is missing' >&2; exit 1; \
	}
	@work="$$(mktemp -d)"; trap 'rm -rf -- "$$work"' EXIT; \
	fixture="$$work/router-fixture.so"; \
	$(CC) -std=c11 -shared -fPIC -O2 -Wall -Wextra -Werror \
		-o "$$fixture" integration/testfixtures/router_fixture.c; \
	for scenario in $(CPA_ROUTER_FIXTURE_SCENARIOS); do \
		echo "Router fixture blackbox (isolated go test process): $$scenario"; \
		CYBER_ABUSE_GUARD_PLUGIN="$(SO)" \
		CYBER_ABUSE_GUARD_ROUTER_FIXTURE_PLUGIN="$$fixture" \
		CYBER_ABUSE_GUARD_VERSION="$(ARTIFACT_VERSION)" \
		CYBER_ABUSE_GUARD_ROUTER_SCENARIO="$$scenario" \
		CYBER_ABUSE_GUARD_REQUIRE_HOST_INTEGRATION=1 \
		CGO_ENABLED=1 $(GO) test -tags=integration,$(TEST_TAGS) -v -count=1 \
			-run='^TestCPAPluginHostRouterFixtureMatrix$$' ./integration || exit $$?; \
	done

cpa-host-fixture-contract:
	@listed="$$($(GO) -C integration/pluginstorecontract test -list='^(TestOfficialCPAHostRoutingSourceContract|TestCPAHostFailOpenFixtureContract)$$' .)" || exit $$?; \
	for test_name in TestOfficialCPAHostRoutingSourceContract TestCPAHostFailOpenFixtureContract; do \
		printf '%s\n' "$$listed" | grep -Fxq "$$test_name" || { \
			echo "required CPA Host source-contract test $$test_name is missing" >&2; exit 1; \
		}; \
	done; \
	$(GO) -C integration/pluginstorecontract test -count=1 -v \
		-run='^(TestOfficialCPAHostRoutingSourceContract|TestCPAHostFailOpenFixtureContract)$$' .

cpa-latest-compat:
	GO=$(GO) bash ./scripts/cpa-latest-compat.sh

management-proxy-413-test:
	bash ./scripts/management-proxy-413-test.sh

ruleset-manifest:
	GO=$(GO) VERSION=$(VERSION) ./scripts/release-ruleset-manifest.sh

sbom:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/release-sbom.sh

vulncheck:
	$(GOVULNCHECK) ./...

round6-vulncheck:
	$(GOVULNCHECK) $(ROUND6_SAFE_PACKAGES)

round6-cpa-store-contract:
	@artifacts=("$(SO)" "$(STORE_ZIP)" "$(DIST_DIR)/build-metadata.json" "$(DIST_DIR)/checksums.txt"); \
	missing=(); \
	for artifact in "$${artifacts[@]}"; do [[ -f "$$artifact" ]] || missing+=("$$artifact"); done; \
	if [[ $${#missing[@]} -eq 0 ]]; then \
		echo 'CPA store contract: validating published dist identity plus repeat-skip and tamper-repair lifecycle'; \
		DIST_DIR="$(DIST_DIR)" $(GO) -C integration/pluginstorecontract test -count=1 .; \
	elif [[ "$(REQUIRE_DIST_ARTIFACTS)" == "1" ]]; then \
		printf 'required published dist artifact is missing: %s\n' "$${missing[@]}" >&2; \
		exit 1; \
	else \
		echo 'CPA store contract: dist artifacts absent; running synthetic source contract only'; \
		env -u DIST_DIR $(GO) -C integration/pluginstorecontract test -count=1 .; \
	fi

release-preflight:
	GO=$(GO) VERSION=$(VERSION) ./scripts/release-preflight.sh

package-release:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/package-release.sh

package-source-release:
	GO=$(GO) VERSION=$(VERSION) ./scripts/package-source-release.sh

release-evidence:
	GO=$(GO) VERSION=$(VERSION) ./scripts/generate-release-evidence.sh

release-doc-consistency:
	./scripts/release-doc-consistency.sh

release-doc-consistency-test:
	./scripts/release-doc-consistency-test.sh

external-release-attestation:
	EXPECTED_TAG="$(ROUND6_CANDIDATE_TAG)" \
	EXPECTED_COMMIT="$(ROUND6_ATTESTED_COMMIT)" \
	EXPECTED_TREE="$(ROUND6_ATTESTED_TREE)" \
	CANDIDATE_RUN_ID="$(ROUND6_CANDIDATE_RUN_ID)" \
	EXPECTED_SO_SHA256="$(ROUND6_CANDIDATE_SO_SHA256)" \
	EXPECTED_STORE_ZIP_SHA256="$(ROUND6_CANDIDATE_STORE_ZIP_SHA256)" \
		./scripts/verify-external-release-attestation.sh "$(RELEASE_EXTERNAL_ATTESTATION)"

frozen-evaluation-v10-tree:
	./scripts/verify-frozen-evaluation-v10-tree.sh

formal-release:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) GOVULNCHECK=$(GOVULNCHECK) \
		./scripts/formal-release.sh

release: release-preflight external-release-attestation frozen-evaluation-v10-tree round6-format-check round6-git-diff-check round6-module-verify test round6-vet race \
	fuzz-smoke round6-script-test corpus-regression development-public-jailbreak-corpus \
	cpa-host-fixture-contract cpa-latest-compat management-proxy-413-test \
	round4-regression round5-regression round6-regression round6-benchmark integration-test \
	round6-vulncheck sbom package-release cpa-store-contract

verify-release:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/verify-release.sh

cpa-store-contract:
	@artifacts=("$(SO)" "$(STORE_ZIP)" "$(DIST_DIR)/build-metadata.json" "$(DIST_DIR)/checksums.txt"); \
	missing=(); \
	for artifact in "$${artifacts[@]}"; do [[ -f "$$artifact" ]] || missing+=("$$artifact"); done; \
	if [[ $${#missing[@]} -eq 0 ]]; then \
		echo 'CPA store contract: validating published dist identity plus repeat-skip and tamper-repair lifecycle'; \
		DIST_DIR="$(DIST_DIR)" $(GO) -C integration/pluginstorecontract test -count=1 ./...; \
	elif [[ "$(REQUIRE_DIST_ARTIFACTS)" == "1" ]]; then \
		printf 'required published dist artifact is missing: %s\n' "$${missing[@]}" >&2; \
		exit 1; \
	else \
		echo 'CPA store contract: dist artifacts absent; running synthetic source contract only'; \
		env -u DIST_DIR $(GO) -C integration/pluginstorecontract test -count=1 ./...; \
	fi

verification-fault-test:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) \
		./scripts/release-verification-fault-test.sh

artifact-hash:
	cd $(DIST_DIR) && sha256sum -c checksums.txt
	cd $(DIST_DIR) && sha256sum -c $(notdir $(SO)).sha256
	cd $(DIST_DIR) && sha256sum -c ruleset.sha256

reproducibility-test:
	GO=$(GO) VERSION=$(VERSION) CYCLONEDX_GOMOD=$(CYCLONEDX_GOMOD) \
		CYCLONEDX_GOMOD_VERSION=$(CYCLONEDX_GOMOD_VERSION) ./scripts/reproducibility-test.sh

clean-tree-check:
	@test -z "$$(git status --porcelain)" || { git status --short >&2; exit 1; }

tools:
	GOBIN="$$($(GO) env GOPATH)/bin" $(GO) install \
		github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION)
	GOBIN="$$($(GO) env GOPATH)/bin" $(GO) install \
		golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

clean:
	rm -rf $(DIST_DIR) build integration/.work coverage.out
	rm -f ./*.test
