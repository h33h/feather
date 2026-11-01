"""Public IPA failures; never serialize arbitrary exception text across trust boundaries."""

EXPECTED_IPA_FAILURES = frozenset(
    {
        "SOURCE_LIMIT",
        "SOURCE_DIGEST_MISMATCH",
        "INPUT_TOO_LARGE",
        "ARCHIVE_INVALID",
        "ARCHIVE_LIMIT",
        "ARCHIVE_METADATA_LIMIT",
        "ZIP_PATH_REJECTED",
        "ZIP_ENTRY_REJECTED",
        "MAIN_APP_REQUIRED",
        "COMPONENT_GRAPH_REJECTED",
        "NESTED_APP_UNSUPPORTED",
        "UNMODELED_EXECUTABLE",
        "EXTENSION_ID_MISMATCH",
        "METADATA_LIMIT",
        "METADATA_INVALID",
        "BINARY_LIMIT",
        "MIN_OS_MISMATCH",
        "MACHO_BOUNDS",
        "MACHO_UNSUPPORTED",
        "FAT_BOUNDS",
        "FAT_METADATA_MISMATCH",
        "FAT_ARCHITECTURE_DUPLICATE",
        "FAT_ARCHITECTURE_MISMATCH",
        "ARCHITECTURE_UNSUPPORTED",
        "DYLIB_TYPE_REQUIRED",
        "SEGMENT_BOUNDS",
        "SECTION_BOUNDS",
        "PLATFORM_INVALID",
        "PLATFORM_UNSUPPORTED",
        "DRM_UNSUPPORTED",
        "SIGNATURE_BOUNDS",
        "ENTITLEMENTS_INVALID",
        "ENTITLEMENTS_MISMATCH",
        "ENTITLEMENTS_VALUE_UNSUPPORTED",
        "DER_ENTITLEMENTS_UNSUPPORTED",
        "LINUX_FAT_SOURCE_UNSUPPORTED",
        "LINUX_SOURCE_CAPACITY_UNSUPPORTED",
    }
)


class ExpectedGuestFailure(ValueError):
    """Created only after an authenticated, request-bound guest failure is verified."""

    def __init__(self, code):
        if code not in EXPECTED_IPA_FAILURES:
            raise ValueError("GUEST_RESPONSE_UNTRUSTED")
        super().__init__(code)
        self.code = code


def expected_ipa_failure(error):
    if (
        isinstance(error, ValueError)
        and len(error.args) == 1
        and isinstance(error.args[0], str)
        and error.args[0] in EXPECTED_IPA_FAILURES
    ):
        return error.args[0]
    return None
