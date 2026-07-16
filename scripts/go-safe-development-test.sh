#!/usr/bin/env bash
set -euo pipefail

mode="${1:-test}"
go_bin="${GO:-go}"
test_tags="${TEST_TAGS:-sqlite_omit_load_extension}"
root="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
cd "$root"

safe_packages=(
  ./cmd/cyber-abuse-guard
  ./cmd/development-adversarial-v11-prep-validator
  ./cmd/development-public-jailbreak-patterns-v1-validator
  ./internal/audit
  ./internal/buildinfo
  ./internal/config
  ./internal/extract
  ./internal/fixturepublish
  ./internal/plugin
  ./internal/rules
  ./internal/subject
  ./rules
)
compile_only_packages=(
  ./cmd/evaluation-snapshot-hash
  ./cmd/evaluation-v10-author
  ./cmd/evaluation-v4-author
  ./cmd/evaluation-v5-author
  ./cmd/evaluation-v6-author
  ./cmd/evaluation-v7-author
  ./cmd/evaluation-v7-validator
  ./cmd/evaluation-v8-author
  ./cmd/evaluation-v9-author
  ./cmd/holdout-fixtures
  ./cmd/holdout-v3-author
)
excluded_packages=(
  "${compile_only_packages[@]}"
  ./integration
  ./internal/classifier
)

declare -A safe_package_set=() excluded_package_set=() package_seen=()
for package in "${safe_packages[@]}"; do
  safe_package_set["$package"]=1
done
for package in "${excluded_packages[@]}"; do
  excluded_package_set["$package"]=1
done
module_path="$("$go_bin" list -m)"
listed_package_output="$("$go_bin" list ./...)"
mapfile -t listed_packages <<<"$listed_package_output"
for full_package in "${listed_packages[@]}"; do
  relative_package="./${full_package#"$module_path"/}"
  if [[ "$full_package" == "$module_path" ]]; then
    relative_package="."
  fi
  if [[ ! -v safe_package_set["$relative_package"] && ! -v excluded_package_set["$relative_package"] ]]; then
    printf 'unreviewed Go package is outside the development test boundary: %s\n' "$relative_package" >&2
    exit 1
  fi
  package_seen["$relative_package"]=1
done
for package in "${safe_packages[@]}" "${excluded_packages[@]}"; do
	if [[ ! -v package_seen["$package"] ]]; then
    printf 'reviewed Go package is missing from the module: %s\n' "$package" >&2
    exit 1
	fi
done

join_regex() {
  local joined="" name
  for name in "$@"; do
    joined+="${joined:+|}${name}"
  done
  printf '^(%s)$' "$joined"
}

# Fifth-round extractor audit regressions are safe development tests. Keep an
# explicit name allowlist so renaming or accidentally dropping one fails closed
# before the broader safe-package run.
expected_round5_extract_entries=(
  TestExtractRawPartsToolTransactionSharesPartBudget
  TestExtractRequestConflictingMediaMarkersAreOrderInvariant
  TestExtractRequestInheritedMediaKindUsesChildExplicitMarker
  TestExtractTextToolTransactionSharesPartBudget
  TestRound5LargeTopLevelToolDefinitionsRemainInspectableWithoutRoleIndex
)
round5_extract_pattern="$(join_regex "${expected_round5_extract_entries[@]}")"
listed_round5_extract_tests="$(
  "$go_bin" test ./internal/extract \
    -list "$round5_extract_pattern"
)"
for name in "${expected_round5_extract_entries[@]}"; do
  if ! grep -Fxq "$name" <<<"$listed_round5_extract_tests"; then
    printf 'required safe round-five extractor entry is missing: %s\n' "$name" >&2
    exit 1
  fi
done

# Every classifier test-like entry is explicitly classified. The safe list is
# the only set executed by development test/race modes; the consumed list is
# compiled and listed but never selected, except for the three v10 aggregate
# boundary checks below. Any new test, fuzz target, benchmark, or example fails
# closed until it is reviewed and added to exactly one list.
expected_safe_classifier_entries=(
  BenchmarkClassifier
  BenchmarkClassifierCandidateRichMaxParts
  BenchmarkClassifierLargeBenign
  BenchmarkClassifierLargePunctuation
  BenchmarkClassifierRoleAwareConversation
  BenchmarkMetaOverrideBilingualMixed
  BenchmarkMetaOverrideLongPrompt
  BenchmarkMetaOverrideManyParts
  FuzzDefensiveQuotedSampleBoundary
  FuzzClassifier
  FuzzMetaOverrideClausePermutation
  FuzzMetaOverrideEncodingAndPartSplit
  TestAnalyzeDoesNotReturnPromptFragments
  TestAssistantClosedQuoteCannotHideNewOperationalSentence
  TestAssistantOperationalTextInsideClosedQuoteRemainsInert
  TestAssistantQuoteScopeCannotHideNewOperationalTurn
  TestAssistantRefusalMayQuoteCoordinatedAttackInertly
  TestAssistantTrailingQuoteCannotLaunderOperationalRestatement
  TestAssistantUnquotedRestatementCannotHideNewOperationalSentence
  TestAssistantUnrelatedQuoteCannotLaunderOperationalRestatement
  TestAuthorizationAloneDoesNotOverrideProtectedAbuse
  TestBalancedCorpusMetrics
  TestBehaviorGraphCoversEightCyberAbuseCategories
  TestBenignAuthorizationContextCarriesAcrossParts
  TestBilingualSemanticAndCuratedTypoTaxonomy
  TestCandidateRichMaxPartsAllocationBound
  TestClassifierAdversarialPerformanceAcceptance
  TestClassifierAllowsExplicitBenignSecurityContexts
  TestClassifierBlocksTerseOperationalAbuse
  TestClassifierCombinesPartsWithoutKeywordInflation
  TestClassifierConcurrentAnalyze
  TestClassifierHighRiskOperationalPrompts
  TestClassifierNeverBlocksOnOneEvidenceGroup
  TestClassifierNFKCAndModeSemantics
  TestClassifierNormalizesCommonHomoglyphs
  TestClassifierPerformanceAcceptance
  TestClassifierPolicyControlsContextAndAuthorization
  TestClassifierPolicyIdentity
  TestClassifierRepeatedConcurrencyAndResourceSanity
  TestCommonPastTenseOperationalAbuse
  TestCompactEvidenceDoesNotCrossParts
  TestCompactMatcherHandlesUnderscoresAndShortLiterals
  TestCompactMatcherPreservesEnglishWordBoundaries
  TestContextLabelDoesNotOverrideOperationalRealTarget
  TestContextLabelsCannotCoverImperativeAbuse
  TestContextPolicyFlagsAreIndependentlyApplied
  TestCredentialObjectFallbackRequiresOperationalTargetAndEvasion
  TestCrossCategoryMaliciousGoalThenImplementationFollowUp
  TestCuratedTyposDoNotBecomeSingleSignalBlocks
  TestDevelopmentAuthorizationCannotOverrideConflictingHarm
  TestDevelopmentCategorySpecificityMatrix
  TestDevelopmentContextPolarityDoesNotReverseRisk
  TestDevelopmentEnglishBoundariesAndSharedPhrasesDoNotInflate
  TestDevelopmentLegitimateWorkflowCannotLaunderExplicitHarm
  TestDevelopmentMinimumContrastPairs
  TestDevelopmentPriorTargetConflictInvalidatesCarriedAuthorization
  TestDevelopmentRound2BenignPurposeControls
  TestDevelopmentRound2NaturalOperationalIntent
  TestDevelopmentRound2NegationAndPurposeScope
  TestDevelopmentRound3LegitimateOutcomeControls
  TestDevelopmentRound3OutcomeOrientedAbuse
  TestDevelopmentRound3ThreeTurnOperationPlans
  TestDevelopmentRound4BalancedSemanticMatrix
  TestDevelopmentSemanticBoundaryAndEvidenceOwnership
  TestDevelopmentSemanticCompositionDoesNotCrossDirectiveClauses
  TestExfiltrationNaturalParaphrases
  TestExplicitNoPermissionClearsLabContext
  TestExplicitPolicyDraftIsNotTreatedAsOperationalAbuse
  TestHardThresholdBlocksEveryEnabledMode
  TestImplementationFollowUpAndRefusalScope
  TestLegitimateWorkflowScopeDoesNotHideHostileCredentialOrEncryptionGoals
  TestMaliciousSystemPolicyCannotNegateRefusalInsteadOfAbuse
  TestMatcherHandlesASCIIEvidenceAdjacentToChinese
  TestMetaOverrideAcrossAdjacentTurnsAndObfuscation
  TestMetaOverrideAmplifiesCyberAbuseWithoutReplacingTaxonomy
  TestMetaOverrideAmplifiesOnlyTheWinningOrdinaryCandidate
  TestMetaOverrideClauseBudgetPerformance
  TestMetaOverrideClauseBudgetRejectsDefensiveCredit
  TestMetaOverrideConnectorFloodAllocationBound
  TestMetaOverrideDefensiveAnalysisAndQuotedMaterialAllow
  TestMetaOverrideDirectDisclosureRequestAudits
  TestMetaOverrideLabelsRemainControlSignalsWithoutBaseBehavior
  TestMetaOverrideNinthLinkedPartRetainsEarlierFamilies
  TestMetaOverrideReconstructsIsolatedUserSegments
  TestMetaOverrideRoleAndToolProvenance
  TestMetaOverrideSingleDisclosurePhraseDoesNotAccumulateRisk
  TestMetaOverrideStrongControlPlaneAttacksAreAuditOnly
  TestMultiTurnSafetyFramingCannotCoverImplementation
  TestNegationPhraseCannotBypassCurrentOperationalAbuse
  TestNegativeAuthorizationClearsLabLaundering
  TestNoPermissionIssuesDoesNotClearAuthorizedLabContext
  TestNoRansomwareCrossMatchForCredentialRequest
  TestNormalizationAndPartBudgetsAreBounded
  TestNormalizedRuneBufferScrubsPromptDerivedStorage
  TestOfflineForensicsSafetyClauseCannotWashOperationalOverride
  TestPriorDefensiveContextDoesNotSanitizeCurrentAbuse
  TestPriorNegatedPolicyDoesNotPoisonImplementationFollowUp
  TestPriorPolicyTermsDoNotPoisonUnrelatedCurrentTurn
  TestPriorSafetyContextDoesNotSanitizeLaterAbuse
  TestProtectedAuthorizationAcrossPartsDoesNotBypass
  TestQualifiedNeutralCoreBecomesOperationalAbuse
  TestRoleAwareClassifierNeverSilentlyAgesOutAbuse
  TestRoleAwareClearSafetyContentIsNotAttributedAsIntent
  TestRoleAwareExplicitNonUserAbuseStillBlocks
  TestRoleAwareNonUserExamplesDoNotPolluteSafeUser
  TestRoleAwareNonUserSafetyExampleDoesNotSupplyUserFollowUpIntent
  TestRoleAwareOnlyCarriesGenuinelyAdjacentUserFollowUp
  TestRoleAwareProviderRefusalWithBenignToolPayloadAllows
  TestRoleAwareProviderToolPayloadAlwaysScanned
  TestRoleAwareSafetyFramingCannotHideOperationalOverride
  TestRoleAwareSafetyFramingWithBenignContinuationAllows
  TestRoleAwareTruncatedDefensiveReconstructionKeepsWrapperFinding
  TestRoleAwareUnknownProvenanceUsesConservativeFallback
  TestRoleAwareUserFollowUpSkipsAssistantRefusal
  TestRound5AgenticEscalationAmplifiesButDoesNotReplaceBaseTaxonomy
	TestRound5AdjacentCompactIntentNegationFailsClosed
  TestRound5AdjacentNegationCandidateFloodFailsClosed
  TestRound5AdjacentNegationCandidateFloodPerformanceAcceptance
	TestRound5AdjacentOverflowPreservesAllMatchedCores
  TestRound5AdjacentPartsNegationReversalCannotHideAbuse
  TestRound5AdjacentPartsNegationReversalSurvivesTrailingParts
  TestRound5AdjacentReversalUsesConfiguredHardBlockThreshold
  TestRound5AdjacentUserSegmentsNegationReversalCannotHideAbuse
  TestRound5CoordinatedCrossCategoryProhibitionsRemainBenign
  TestRound5CrossCategoryNegationDoesNotCoverOperationalTail
	TestRound5DirectiveBoundaryRunsPreserveSentenceBreaks
	TestRound5EarlierLiteralNegationCannotHideLaterCompactClause
  TestRound5LargeAdjacentNegationReconstructionFailsClosed
	TestRound5LongNegationReversalBridgeFailsActive
	TestRound5NegatedProhibitionModalBridgeFailsActive
	TestRound5MetaOverrideBenignNearNeighborsAllow
  TestRound5MetaOverrideBilingualFamilies
  TestRound5MetaOverrideDefensiveQuotedSamplesRemainInert
  TestRound5MetaOverrideDefensiveTailCannotAuthorizeExecution
  TestRound5MetaOverrideFamiliesProduceFixedEvidence
  TestRound5MetaOverridePerformanceAcceptance
  TestRound5MalformedUTF8DirectiveBoundariesConsumeDecodedWidth
  TestRound5NegationCannotHideLaterActiveIntent
  TestRound5PersistentBlockSurvivesIncidentalLowScoreTaxonomyTerms
  TestRound5PersistentInstructionInjectionAcrossLinkedUserSegments
  TestRound5PersistentInstructionInjectionBlocksOnlyActiveSafetyOverride
  TestRound5RefusalScopeOutputAndCompoundIntentHardening
  TestRound5NegationReversalKeepsTrueProhibitionsBenign
	TestRound5NormalizedContractionsRemainNegationReversals
	TestRound5RepeatedIntentYInflectionsFailActive
	TestRound5UnrelatedPassiveNegationCannotLaunderMetaTarget
  TestRound5UnrelatedSignalsDoNotPolluteMetaTail
  TestRound5WrapperAuditSurvivesIncidentalLowScoreTaxonomyTerms
  TestSafetyLabelsCannotWashOutOperationalAbuse
  TestSameCategoryEvidenceCompositionIsScopedAndConservative
  TestScopedAuthorizationNamingActionCarriesForNonProtectedCategory
  TestScopedExplanationAndConceptualPhrasesAreAllowed
  TestScopedNegationAllowsProhibitionsButNotNegationBait
  TestSystemClosedQuoteCannotHideNewOperationalSentence
  TestUnrelatedPriorQualifierDoesNotInflateCurrentBenignAnalysis
  TestUnscopedPriorLabDoesNotCoverRealTarget
  TestUntrustedPartsFallbackScansOlderPartsAndReportsCapacity
  TestValidUTF8PrefixHandlesInteriorInvalidByte
  TestWrapperBaseBehaviorMinimalContrasts
  TestWrapperOnlyNeverBlocksAnyMode
)
expected_consumed_tests=(
  TestEvaluationV10Integrity
  TestEvaluationV10HistoricalSnapshotRecordIntegrity
  TestEvaluationV10ConsumedRerunRejected
  TestIndependentHoldoutV10
  TestEvaluationV4Integrity
  TestEvaluationV4ProductionSnapshotIntegrity
  TestIndependentHoldoutV4
  TestEvaluationV5Integrity
  TestEvaluationV5ProductionSnapshotIntegrity
  TestIndependentHoldoutV5
  TestEvaluationV6Integrity
  TestEvaluationV6ProductionSnapshotIntegrity
  TestIndependentHoldoutV6
  TestEvaluationV7Integrity
  TestEvaluationV7ProductionSnapshotIntegrity
  TestIndependentHoldoutV7
  TestEvaluationV8Integrity
  TestEvaluationV8ProductionSnapshotIntegrity
  TestIndependentHoldoutV8
  TestEvaluationV9Integrity
  TestEvaluationV9HistoricalSnapshotRecordIntegrity
  TestEvaluationV9ConsumedRerunRejected
  TestIndependentHoldoutV9
  TestRetiredHoldoutV1Diagnostic
  TestRetiredHoldoutV1FrozenIntegrity
  TestRetiredHoldoutV1ThresholdDiagnosticsRejectFailures
  TestRetiredHoldoutV2Gate
  TestIndependentHoldoutV2FrozenIntegrity
  TestIndependentHoldoutV3FrozenIntegrity
  TestIndependentHoldoutV3Gate
)

declare -A safe_seen=() consumed_seen=()
for name in "${expected_safe_classifier_entries[@]}"; do
  if [[ -v safe_seen["$name"] || -v consumed_seen["$name"] ]]; then
    printf 'duplicate classifier allowlist entry: %s\n' "$name" >&2
    exit 1
  fi
  safe_seen["$name"]=0
done
for name in "${expected_consumed_tests[@]}"; do
  if [[ -v safe_seen["$name"] || -v consumed_seen["$name"] ]]; then
    printf 'duplicate classifier allowlist entry: %s\n' "$name" >&2
    exit 1
  fi
  consumed_seen["$name"]=0
done

listed_test_output="$(
  "$go_bin" test -tags="$test_tags" ./internal/classifier \
    -list '^(Test|Fuzz|Benchmark|Example)'
)"
mapfile -t listed_tests <<<"$listed_test_output"
for name in "${listed_tests[@]}"; do
  [[ "$name" =~ ^(Test|Fuzz|Benchmark|Example)[A-Za-z0-9_]*$ ]] || continue
  if [[ -v safe_seen["$name"] ]]; then
    safe_seen["$name"]=1
  elif [[ -v consumed_seen["$name"] ]]; then
    consumed_seen["$name"]=1
  else
    printf 'unclassified classifier test-like entry: %s\n' "$name" >&2
    exit 1
  fi
done

for name in "${expected_safe_classifier_entries[@]}"; do
  if [[ "${safe_seen[$name]}" != 1 ]]; then
    printf 'required safe classifier entry is missing: %s\n' "$name" >&2
    exit 1
  fi
done
for name in "${expected_consumed_tests[@]}"; do
  if [[ "${consumed_seen[$name]}" != 1 ]]; then
    printf 'required consumed-boundary test name is missing: %s\n' "$name" >&2
    exit 1
  fi
done

safe_pattern="$(join_regex "${expected_safe_classifier_entries[@]}")"
boundary_pattern="$(join_regex \
  TestEvaluationV10Integrity \
  TestEvaluationV10HistoricalSnapshotRecordIntegrity \
  TestEvaluationV10ConsumedRerunRejected)"

case "$mode" in
  test)
    # Compile/link authoring and historical tooling tests without selecting any
    # test function or opening their evaluation/holdout fixtures.
    "$go_bin" test -tags="$test_tags" -count=1 -run='^$' "${compile_only_packages[@]}"
    "$go_bin" test -tags="$test_tags" -count=1 "${safe_packages[@]}"
    "$go_bin" test -tags="$test_tags" -count=1 -run="$safe_pattern" ./internal/classifier
    ;;
  race)
    CGO_ENABLED=1 "$go_bin" test -race -tags="$test_tags" -count=1 -run='^$' "${compile_only_packages[@]}"
    CGO_ENABLED=1 "$go_bin" test -race -tags="$test_tags" -count=1 "${safe_packages[@]}"
    CGO_ENABLED=1 "$go_bin" test -race -tags="$test_tags" -count=1 -run="$safe_pattern" ./internal/classifier
    ;;
  boundary)
    "$go_bin" test -tags="$test_tags" -count=1 -run='^$' "${compile_only_packages[@]}"
    "$go_bin" test -tags="$test_tags" -count=1 -v -run="$boundary_pattern" ./internal/classifier
    ;;
  *)
    printf 'usage: %s test|race|boundary\n' "${0##*/}" >&2
    exit 2
    ;;
esac
