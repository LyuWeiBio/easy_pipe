"""Controller-side FASTQ classification and pairing public API."""

from biopipe.detectors.fastq import (
    assess_generic_fastq,
    assess_illumina_fastq,
    detect_fastq_dataset,
)
from biopipe.detectors.models import (
    Compression,
    DetectorAssessment,
    FastqDetectionResult,
    FastqFileFacts,
    HeaderFamily,
    MateMarkerCounts,
    NamingConvention,
    PairingSlotFacts,
    PairingStatus,
    ParsedFastqName,
    ReadDirection,
    SamplePairingFacts,
)
from biopipe.detectors.naming import parse_fastq_filename

__all__ = [
    "Compression",
    "DetectorAssessment",
    "FastqDetectionResult",
    "FastqFileFacts",
    "HeaderFamily",
    "MateMarkerCounts",
    "NamingConvention",
    "PairingSlotFacts",
    "PairingStatus",
    "ParsedFastqName",
    "ReadDirection",
    "SamplePairingFacts",
    "assess_generic_fastq",
    "assess_illumina_fastq",
    "detect_fastq_dataset",
    "parse_fastq_filename",
]
