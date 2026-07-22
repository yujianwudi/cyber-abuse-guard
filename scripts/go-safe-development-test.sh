#!/usr/bin/env bash
set -euo pipefail

mode="${1:-test}"
go_bin="${GO:-go}"
test_tags="${TEST_TAGS:-sqlite_omit_load_extension}"
root="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
cd "$root"
round8_counted_mock_module="integration/round8countedmock"

safe_packages=(
  ./cmd/cyber-abuse-guard
  ./cmd/development-adversarial-v11-prep-validator
  ./cmd/development-public-jailbreak-patterns-v1-validator
  ./internal/audit
  ./internal/buildinfo
  ./internal/config
  ./internal/extract
  ./internal/explanation
  ./internal/fixturepublish
  ./internal/plugin
  ./internal/round8test
  ./internal/rules
  ./internal/subject
  ./rules
)
for package in "${safe_packages[@]}" ./internal/classifier; do
  if ! "$go_bin" list -tags="$test_tags" "$package" >/dev/null; then
    printf 'required Round6 safe package is missing or unloadable: %s\n' "$package" >&2
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

require_reviewed_entries() {
  local package="$1" label="$2" discovery_pattern="$3" listed name
  shift 3
  local -A reviewed=()
  for name in "$@"; do
    if [[ -v reviewed["$name"] ]]; then
      printf 'duplicate safe %s allowlist entry: %s\n' "$label" "$name" >&2
      exit 1
    fi
    reviewed["$name"]=0
  done
  listed="$(
    "$go_bin" test -tags="$test_tags" "$package" \
      -list "$discovery_pattern"
  )"
  while IFS= read -r name; do
    [[ "$name" =~ ^(Test|Fuzz|Benchmark|Example)[A-Za-z0-9_]*$ ]] || continue
    if [[ ! -v reviewed["$name"] ]]; then
      printf 'unclassified safe %s entry: %s\n' "$label" "$name" >&2
      exit 1
    fi
    reviewed["$name"]=1
  done <<<"$listed"
  for name in "$@"; do
    if [[ "${reviewed[$name]}" != 1 ]]; then
      printf 'required safe %s entry is missing: %s\n' "$label" "$name" >&2
      exit 1
    fi
  done
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

# Round8 added public, synthetic-only audit/provenance/router regressions. These
# packages are still executed in full below; this reviewed list additionally
# fails closed if a required production-FP or privacy contract is renamed or
# dropped. No restricted evaluation, retired holdout, or private fixture is
# compiled or inspected here.
expected_round8_audit_entries=(
  TestRound8AuditReadRejectsInvalidPersistedEvent
  TestRound8DecisionExplanationReadAcceptsInternallyConsistentSQLiteRewrite
  TestRound8DecisionExplanationReadRejectsCrossFieldInconsistentSQLiteRow
  TestRound8DecisionExplanationRejectsCrossFieldContradictions
  TestRound8DecisionExplanationRejectsUnsafeOrUnboundedMetadata
  TestRound8DecisionExplanationRejectsUnknownHardFloorReasonAfterJSONDecode
  TestRound8DecisionExplanationValidationCloneAndRoundTrip
  TestRound8RawCaptureCanonicalAliasesHashAndRedactionMetadata
  TestRound8RawCaptureDeduplicatesWithinTTLAndRenewsAtBoundary
  TestRound8RawCaptureDeduplicatesWithoutPersistingRequestHash
  TestRound8RawCaptureReadRejectsMalformedPersistedRows
  TestRound8RawCaptureWriteValidationKeepsPriorityEvent
  TestRound8StatsRetryWindowSemantics
  TestRound8StatsSeparateEventsUniqueRepeatsAndUnhashed
  TestRound8StatsUsesSingleSnapshotDuringConcurrentWrites
  TestV3DatabaseMigratesThroughRawCaptureSchemaV5
  TestV4MigrationBackupNeverRetainsRawCaptures
  TestV4MigrationRejectsMalformedRawCaptureBeforePublishingBackup
  TestV4RawCaptureMigrationKeepsFirstLiveCaptureAndCreatesPartialUniqueRawSHAIndex
  TestV4RawCaptureMigrationReplaysV5TTLWindowsAndPreservesEventAssociation
  TestV5ContractFailureRollsBackSchemaVersionAndCaptureDeduplication
)
expected_round8_extract_entries=(
  TestRound8ContentKindNamesAreClosed
  TestRound8Exact16KiBAnd300KiBStreamingTextPlacement
  TestRound8ExactProtocolTextPartCounts
  TestRound8FencedCodeProtocolMatrix
  TestRound8FencedLanguageKindsAndPlainFallback
  TestRound8FencedPlannerCrossesDecoderChunks
  TestRound8FencedSegmentationBudgetAbortsBeforePartialField
  TestRound8FencedSegmentationUsesExactAlignedChunkBudget
  TestRound8FencedSyntaxPreservesSystemDeveloperAndHistoryMetadata
  TestRound8FencesCannotCrossSiblingJSONStrings
  TestRound8IndependentToolCallsHaveIsolatedScopes
  TestRound8MultipartTextFieldsHaveIndependentScopes
  TestRound8ProtocolTurnScopeAndSchemaMatrix
  TestRound8ToolCallAndResultContentKindMatrix
)
expected_round8_plugin_entries=(
  TestAuditDecisionExplanationHonorsIdentifierLoggingPolicy
  TestAuditDecisionExplanationIsBoundedAndTextFree
  TestRound8BalancedRouterSeededPairedMutationMatrix
  TestRound8BalancedRouterSyntheticProductionFalsePositivePairs
  TestRound8ChatAndResponsesToolSchemaContamination
  TestRound8ClassifierDecisionExplanationPersistsEndToEnd
  TestRound8DecisionExplanationRequiresClassifierOwnedTopLevelCategory
  TestRound8DecisionExplanationUsesClosedEvidenceDimensionMapping
  TestRound8FencedContentKindRouterProtocolMatrix
  TestRound8FencedLogConfigAndUnclosedRouterBoundary
  TestRound8P1FalsePositiveBoundariesAcrossOpenAIProtocols
  TestRound8RouterHistoricalReactivationBoundary
  TestRound8RoleAwareWrapperScorePersistsAcrossNonUserSegments
  TestRound8SystemFencedEvidenceIsNotAnActiveDirective
)
require_reviewed_entries ./internal/audit "round-eight audit" '^(TestRound8|TestV[345])' "${expected_round8_audit_entries[@]}"
require_reviewed_entries ./internal/extract "round-eight extractor" '^TestRound8' "${expected_round8_extract_entries[@]}"
require_reviewed_entries ./internal/plugin "round-eight plugin" '^(TestRound8|TestAuditDecisionExplanation)' "${expected_round8_plugin_entries[@]}"

expected_round8_classifier_entries=(
	TestRound8ActiveCredentialNounsAloneAreNotHostileConflicts
	TestRound8AmbiguousPayloadPersistenceDoesNotImplyMalware
  TestRound8CompleteNonUserDirectiveRemainsDetectable
  TestRound8CredentialMetadataDoubleNegationCannotClaimNoSecretAccess
  TestRound8CredentialMetadataHarvestDoesNotImplyTheft
  TestRound8CredentialMetadataMarkersCannotSuppressCRED002
  TestRound8CredentialMetadataMarkersCannotSuppressSecretHarvest
  TestRound8CredentialMetadataMayNameNegatedSecretExamples
  TestRound8CredentialMetadataNeighborStillBlocksHostileHarvest
  TestRound8CredentialMetadataNegatedHostileVerbDoesNotCancelSafety
  TestRound8CredentialMetadataSafetyCannotCoverCoordinatedSecretCollection
  TestRound8CredentialMetadataSlashSeparatedSecretExamplesRemainNegated
  TestRound8CredentialTheftActionRequiresWordBoundary
  TestRound8CoreFamilyRoleTurnAndProvenanceMatrix
  TestRound8CurrentTurnOwnershipAndHistoricalReactivation
  TestRound8DirectCarrierTraversesEveryUncancelledAnchor
  TestRound8DirectCarrierProofOverflowIsUnavailable
  TestRound8AffirmativeCarrierProofOverflowIsUnavailable
  TestRound8ExplicitReferentReactivatesHistoricalInertContentKinds
  TestRound8Exact16KiBAnd300KiBClassifierPlacement
  TestRound8GenericDevelopmentVocabularyStress
  TestRound8HardFloorReasonIsEmptyWhenFloorIsNotApplied
  TestRound8HardFloorReasonTracksActualAdmissionPath
  TestRound8HistoricalAndCurrentToolCallOwnership
  TestRound8NearestHistoricalReferentBoundary
  TestRound8HistoricalToolResultReferentReactivation
  TestRound8ManagedHealthHelperDoesNotImplyMalware
  TestRound8ManagedHealthHelperNeighborStillBlocksBackdoor
  TestRound8ManagedHealthHelperPerformanceLanguageDoesNotImplyMalware
  TestRound8NewerBenignInertScopeTerminatesOlderBareReferent
	TestRound8OutcomeCandidateHasCompleteAuditExplanation
	TestRound8OAuthAuthenticationWorkflowsDoNotCreateHostileCredentialConflict
	TestRound8UnrelatedNegationCannotActivateAdjacentOAuthHardBlock
	TestRound8ApprovedCredentialStoreWorkflowsRemainBenign
	TestRound8OAuthWorkflowMarkersCannotWashOutCredentialTheft
	TestRound8OwnedOAuthBackendTransferRemainsBenign
	TestRound8OwnedOAuthApprovedStoreAfterAuthenticationRemainsBenign
	TestRound8CredentialWorkflowMarkersDoNotSuppressRuleTargets
	TestRound8CredentialTheftCoreSynonymsRemainBlocked
	TestRound8PossessiveBrowserTargetsDistinguishConsentFromAcquisition
	TestRound8OwnedOAuthResponseExtractionIsNotCredentialTheft
  TestRound8PersistentMetaBlockHasTruthfulExplanation
  TestRound8ProfiledWrapperRoleCapKeepsBatchAndStreamExplanationsConsistent
  TestRound8ProfiledLongDefensiveQuoteReferentReactivation
  TestRound8ProtocolToolCallScopeIsolationClassification
  TestRound8QuotedOrInertSuppressedExplanation
  TestRound8SameDirectiveCrossesWindowButSeparateMessagesDoNotCompose
  TestRound8SeededOneSlotPairedMutationMatrix
  TestRound8SemanticCorePredicateCapsIncompleteCandidates
	TestRound8SelfContainedCarrierKeepsInertAndDescriptiveBoundaries
	TestRound8SelfContainedCurrentCarrierCannotSplitCoreAcrossAdjacentFences
	TestRound8SelfContainedCurrentCarrierDirectiveCannotBeFencedAway
  TestRound8StreamingMetadataOwnership
  TestRound8StreamingSemanticPotentialUsesCorePredicateAndDynamicThreshold
  TestRound8SyntheticProductionFalsePositivePairs
  TestRound8SyntheticWinningRuleIDsRemainAuditable
  TestRound8OverflowLedgerUsesRealRiskAndPhysicalOrder
  TestRound8RoleAwareWrapperCapReconcilesOwnershipAndHardFloor
)

# Every classifier test-like entry visible without the consumed_evaluation build
# tag is explicitly classified. Restricted evaluation/holdout tests are not
# compiled or listed in development test/race/list modes. Any new visible test,
# fuzz target, benchmark, or example fails closed until it is reviewed here.
expected_safe_classifier_entries=(
  BenchmarkClassifier
  BenchmarkClassifierCandidateRichMaxParts
  BenchmarkClassifierLargeBenign
  BenchmarkClassifierLargePunctuation
  BenchmarkClassifierRoleAwareConversation
  BenchmarkMetaOverrideBilingualMixed
  BenchmarkMetaOverrideLongPrompt
  BenchmarkMetaOverrideManyParts
  BenchmarkRepositoryNeutralAuthorityCatalog
  BenchmarkRound6StreamingOneMiB
  BenchmarkRound6StreamingScale
  FuzzDefensiveQuotedSampleBoundary
  FuzzClassifier
  FuzzMetaOverrideClausePermutation
  FuzzMetaOverrideEncodingAndPartSplit
  FuzzRound6StreamingChunkAndRoleBoundaries
  TestAnalyzeDirectivesHandlesInternalInvalidRuneBoundary
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
  TestClassifierDirectiveAllocationAcceptance
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
  TestControlWeakeningLanguageIsNotDefensiveContext
  TestCredentialObjectFallbackRequiresOperationalTargetAndEvasion
  TestCrossCategoryMaliciousGoalThenImplementationFollowUp
  TestCuratedTyposDoNotBecomeSingleSignalBlocks
  TestDefensiveQuotedCredentialReviewBoundary
  TestDefensiveQuotedCredentialReviewCannotHideSemanticPrefix
  TestDefensiveQuotedCredentialReviewFailsClosed
  TestDefensiveQuotedCredentialReviewFollowUps
  TestDefensiveQuotedCredentialReviewPriorProofBudgetFailsClosed
  TestDefensiveQuotedCredentialReviewPriorProofPerformanceAcceptance
  TestDefensiveQuotedCredentialReviewReferentialImplementationFollowUps
  TestDefensiveQuotedCredentialReviewStreamingReferentialFollowUps
  TestDefensiveQuotedCredentialReviewStreamingRepeatedFields
  TestDefensiveQuotedReviewCrossWindowFollowUpNeverSilentlyAllows
  TestDefensiveQuotedReviewLongStreamingReferentialFollowUps
  TestDefensiveQuotedReviewNegatedReferentRemainsInert
  TestDefensiveQuotedReviewReactivationPreservesDirectReferentResult
  TestDefensiveQuotedReviewReferentClassificationChargesWindowBudget
  TestDefensiveMaintenanceLabelDoesNotLaunderOperationalAbuse
  TestDefensiveMaintenanceRequestsRemainUsable
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
  TestDirectiveClauseOverflowCompositionRetainsOmittedContradiction
  TestDirectiveClauseOverflowCompositionRetainsOmittedCoreContradiction
  TestDirectiveClauseOverflowContradictionIsScopedToProviderPair
	TestDirectiveClauseDifferentProviderActiveCompositionBlocks
	TestDirectiveClauseProviderPairFinalRegressions
  TestDirectiveClauseOverflowPerformanceBoundary
  TestDirectiveClauseOverflowPreservesCompleteProhibition
  TestDirectiveClauseOverflowPreservesMaliciousCategoryTail
  TestExfiltrationNaturalParaphrases
  TestExplicitNoPermissionClearsLabContext
  TestExplicitPolicyDraftIsNotTreatedAsOperationalAbuse
  TestFindingOriginKeepsUserOnlyMultiTurnComposition
  TestFindingOriginMixedUserLikeCompositionRemainsUntrusted
  TestFindingOriginPrefersIndependentTrustedUserOnExactTie
  TestFindingOriginSurvivesStreamingCompatOver64Segments
  TestFindingOriginSurvivesLongStreamingFieldAndClearsWhenIncomplete
  TestFindingOriginTracksWinningRoleAndProvenance
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
  TestMetaOverrideDoesNotPromoteWeakOrdinaryCandidates
  TestMetaOverrideLabelsRemainControlSignalsWithoutBaseBehavior
  TestMetaOverrideNinthLinkedPartRetainsEarlierFamilies
  TestMetaOverrideReconstructsIsolatedUserSegments
  TestMetaOverrideRoleAndToolProvenance
  TestMetaOverrideSingleDisclosurePhraseDoesNotAccumulateRisk
  TestMetaOverrideStrongControlPlaneAttacksAreAuditOnly
  TestMetaOverrideStillAmplifiesQualifiedOrBalancedAttack
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
  TestProfiledMetadataIndexSentinelsDoNotOptLegacySlicesIn
  TestProfiledMetadataNormalizesMixedLegacyIndexesWithoutMutatingCaller
  TestProfiledMetadataUnscopedLegacyAssistantCannotBecomeHistoricalReferent
  TestQualifiedNeutralCoreBecomesOperationalAbuse
  TestResultJSONOmitsZeroCoverage
  TestRoleAwareClassifierNeverSilentlyAgesOutAbuse
  TestRoleAwareClearSafetyContentIsNotAttributedAsIntent
  TestRoleAwareClosedQuotedNonExecutionHistoryRemainsInert
  TestRoleAwareExplicitNonUserAbuseStillBlocks
  TestRoleAwareHistoricalClosureDoesNotAgeOutOtherAbuse
  TestRoleAwareNonUserBaseBehaviorStillBlocksAfterWrapperCap
  TestRoleAwareNonUserExamplesDoNotPolluteSafeUser
  TestRoleAwareNonUserSafetyExampleDoesNotSupplyUserFollowUpIntent
  TestRoleAwareOnlyCarriesGenuinelyAdjacentUserFollowUp
  TestRoleAwareProviderRefusalWithBenignToolPayloadAllows
  TestRoleAwareProviderToolPayloadAlwaysScanned
  TestRoleAwareRefusedHistoricalAttackAllowsNarrowSafetyMaintenance
  TestRoleAwareRefusedHistoricalAttackReactivatesOnExecutionFollowUp
  TestRoleAwareSafetyFramingCannotHideOperationalOverride
  TestRoleAwareSafetyFramingWithBenignContinuationAllows
  TestRoleAwareTruncatedDefensiveReconstructionKeepsWrapperFinding
  TestRoleAwareUnknownProvenanceUsesConservativeFallback
  TestRoleAwareUserFollowUpSkipsAssistantRefusal
  TestRoleAwareWrapperOnlyCapsProvenanceButKeepsRolelessConservative
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
	TestRound5DirectiveBudgetCountsRiskRelevantClauses
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
  TestRound5RepositoryNeutralAuthorityVariants
  TestRound5RepositoryNeutralDomainCatalogStaysWrapperOnly
  TestRound5RefusalScopeOutputAndCompoundIntentHardening
  TestRound5NegationReversalKeepsTrueProhibitionsBenign
	TestRound5NormalizedContractionsRemainNegationReversals
	TestRound5RepeatedIntentYInflectionsFailActive
	TestRound5UnrelatedPassiveNegationCannotLaunderMetaTarget
  TestRound5UnrelatedSignalsDoNotPolluteMetaTail
  TestRound5WrapperAuditSurvivesIncidentalLowScoreTaxonomyTerms
  TestRound6DefaultBudgetCoversMaximumLogicalFieldFragmentation
  TestRound6HardLogicalFieldBoundHasCompleteBudget
  TestRound6IncompleteClearsUnverifiedFinding
  TestRound6NormalizeBytesMatchesStringNormalization
  TestRound6NormalizeBytesRejectsInvalidUTF8
  TestRound6RequiredChunkOverlapFitsConfigurationBudget
  TestRound6SingleWindowHasNoBoundaryReconstruction
  TestRound6StreamingClosedSafetyQuoteDiscardsProvisionalFinding
  TestRound6StreamingClosedSafetyQuoteTailStaysInertAcrossNextUserField
  TestRound6StreamingCompactMatcherSurvivesMoreThanOverlapSeparators
  TestRound6StreamingControlPairDoesNotCarryBaseBehaviorAcrossRoles
  TestRound6StreamingNonUserWrapperCapPreservesLaterBaseBehavior
  TestRound6StreamingCoverageReasonsAreSeparateFromProofBudgets
  TestRound6StreamingCrossWindowLiteralAndNFKC
  TestRound6StreamingCrossWindowPriorAndReferentialFollowUpBecomesIncomplete
  TestRound6StreamingCrossWindowQuotedReviewIsExplicitlyIncomplete
  TestRound6StreamingDoesNotJoinDifferentRoleFields
  TestRound6StreamingInternalChunksDoNotConsumeLogicalPartBudget
  TestRound6StreamingInvalidOrderIsOperationalError
  TestRound6StreamingLateHarmConflictBecomesIncomplete
  TestRound6StreamingLateUnnegatedSyntheticIntentBecomesIncomplete
  TestRound6StreamingLongAssistantQuotedRefusalRemainsInert
  TestRound6StreamingLongAssistantTailDoesNotComposeBaseBehaviorWithUser
  TestRound6StreamingLongPriorUserCoreAndFollowUpBecomesIncomplete
  TestRound6StreamingMappedToolControlRemainsAuditOnly
  TestRound6StreamingMalformedCrossWindowQuotedReviewCannotEraseHardBlock
  TestRound6StreamingNegationAcrossWindowRemainsInert
  TestRound6StreamingNegatedSyntheticIntentRemainsComplete
  TestRound6StreamingPreservesBoundedRoleCompositionsAfterSixtyFourFields
  TestRound6StreamingPreservesShortRoleAwareDecisions
  TestRound6StreamingPreservesThreeTurnRoleSemanticsAfterSixtyFourFields
  TestRound6StreamingProcessesAllSixtyFiveFields
  TestRound6StreamingPriorSafetyWindowDoesNotLaunderLaterInstruction
  TestRound6StreamingProvenLongQuotedReviewRetainsNoPromptBytes
  TestRound6StreamingQuotedSafetyPrefixDoesNotLaunderEarlierInstruction
  TestRound6StreamingSplitSyntheticCoreBecomesIncomplete
  TestRound6StreamingSplitSyntheticQualifiersBecomeIncomplete
  TestRound6StreamingStrictSplitSyntheticCoreBecomesIncomplete
  TestRound6StreamingStrictSplitWrapperOnlyMetaRemainsComplete
  TestRound6StreamingSyntheticFactsStayInsideLogicalField
  TestRound6StreamingSyntheticSafetyQuoteTransactions
  TestRound6StreamingUnclosedSafetyQuoteCommitsProvisionalFinding
  TestRound6StreamingUnclosedSafetyQuoteHarmConflictBecomesIncomplete
  TestRound6StreamingUnquotedTailAfterSafetyQuoteLinksNextUserField
  TestRound6StreamingUnrelatedMetaWindowsDoNotCompose
  TestRound6StreamingUntrustedFallbackPreservesAdjacentProofBudget
  TestRound6StreamingUnknownLongFieldRetainsBoundedRiskFacts
  TestRound6StreamingUnknownPersistentControlPlaneSplitFailsClosed
  TestRound6StreamingUnknownLongBenignFieldDoesNotPromoteSingleRisk
  TestRound6StreamingRiskAfterLongBenignBoundaryFailsClosed
  TestRound6StreamingRepeatedRiskAfterContextBoundaryFailsClosed
  TestRound6StreamingExactUnknownBlockSurvivesLongRiskSuffix
  TestRound6StreamingUnknownToolPayloadClearsRiskBoundary
  TestRound6StreamingKnownRoleClearsUnknownRiskFacts
  TestRound6StreamingLongUnknownBoundaryClearsUserComposition
  TestRound6StreamingUntrustedOverSixtyFourRetainsEarlyAndLateProofs
  TestRound6StreamingPersistentControlPlaneAcrossWindowsBecomesIncomplete
  TestSafetyLabelsCannotWashOutOperationalAbuse
  TestSameCategoryEvidenceCompositionIsScopedAndConservative
  TestScopedAuthorizationNamingActionCarriesForNonProtectedCategory
  TestScopedExplanationAndConceptualPhrasesAreAllowed
  TestScopedNegationAllowsProhibitionsButNotNegationBait
  TestStreamingHistoricalClosureDoesNotAgeOutOtherAbuse
  TestStreamingMetaOverridePromotionRequiresQualifiedOrBalancedOrdinaryRisk
  TestStreamingRefusedHistoricalAttackSafetyMaintenanceBoundary
  TestSystemClosedQuoteCannotHideNewOperationalSentence
  TestUnrelatedPriorQualifierDoesNotInflateCurrentBenignAnalysis
  TestUnscopedPriorLabDoesNotCoverRealTarget
  TestUntrustedPartsFallbackScansOlderPartsAndReportsCapacity
  TestValidUTF8PrefixHandlesInteriorInvalidByte
  TestWrapperBaseBehaviorMinimalContrasts
  TestWrapperOnlyNeverBlocksAnyMode
)
expected_safe_classifier_entries+=("${expected_round8_classifier_entries[@]}")
declare -A safe_seen=()
for name in "${expected_safe_classifier_entries[@]}"; do
	if [[ -v safe_seen["$name"] ]]; then
    printf 'duplicate classifier allowlist entry: %s\n' "$name" >&2
    exit 1
  fi
  safe_seen["$name"]=0
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

safe_pattern="$(join_regex "${expected_safe_classifier_entries[@]}")"
boundary_pattern="$(join_regex \
  TestEvaluationV10Integrity \
  TestEvaluationV10HistoricalSnapshotRecordIntegrity \
  TestEvaluationV10ConsumedRerunRejected)"

case "$mode" in
  list)
    "$go_bin" -C "$round8_counted_mock_module" list . >/dev/null
    round8_entry_count=$((
      ${#expected_round8_audit_entries[@]} +
      ${#expected_round8_extract_entries[@]} +
      ${#expected_round8_plugin_entries[@]} +
      ${#expected_round8_classifier_entries[@]}
    ))
    printf 'Round6 safe development boundary: packages=%d classifier_entries=%d round8_entries=%d\n' \
      "${#safe_packages[@]}" "${#expected_safe_classifier_entries[@]}" "$round8_entry_count"
    ;;
  test)
    "$go_bin" test -tags="$test_tags" -count=1 "${safe_packages[@]}"
    "$go_bin" test -tags="$test_tags" -count=1 -run="$safe_pattern" ./internal/classifier
    "$go_bin" -C "$round8_counted_mock_module" test -count=1 .
    ;;
  race)
    CGO_ENABLED=1 "$go_bin" test -race -tags="$test_tags" -count=1 "${safe_packages[@]}"
    CGO_ENABLED=1 "$go_bin" test -race -tags="$test_tags" -count=1 -run="$safe_pattern" ./internal/classifier
    CGO_ENABLED=1 "$go_bin" -C "$round8_counted_mock_module" test -race -count=1 .
    ;;
  boundary)
    "$go_bin" test -tags="$test_tags,consumed_evaluation" -count=1 -v -run="$boundary_pattern" ./internal/classifier
    ;;
  *)
	printf 'usage: %s list|test|race|boundary\n' "${0##*/}" >&2
    exit 2
    ;;
esac
