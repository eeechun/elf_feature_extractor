# Feature Extractor

A Python package for extracting features from executable files using radare2.
- FCG Extractor:
    Extract function call graphs and the instructions of each function.
- Opcode Extractor:
    Extract opcodes and the section name.

## Installation

```bash
pip install path/to/feature-extractor
```
 
## Dependencies

- radare2 (r2)
- timeout command (usually part of coreutils)

## Usage

```python
import pandas as pd
from feature_extractor import ExtractOpcode, ExtractFCG, check_dependencies

# Check if all dependencies are available
deps_available, message = check_dependencies()
if not deps_available:
    print(f"Missing dependencies:\n{message}")
    exit(1)

# Create feature extractor instance
opcode_extractor = ExtractOpcode()
fcg_extractor = ExtractFCG()

# Prepare input DataFrame
df_input = pd.DataFrame({
    'file_name': ['sample1.exe', 'sample2.exe']
})

# Extract features
opcode_extractor.process_features(
    df_input=df_input,
    dir_feature='output/opcode',
    dir_dataset='samples/dataset',
    timeout_seconds=300,
    dir_log='logs'
)

fcg_extractor.process_features(
    df_input=df_input,
    dir_feature='output/fcg',
    dir_dataset='samples/dataset',
    timeout_seconds=300,
    dir_log='logs'
)
```

## Features

- Extracts function call graphs or opcodes from both standard ELF files and compressed/packed executables
- Handles timeouts gracefully
- Parallel processing for better performance
- Comprehensive logging
- Dependency checking

## License

MIT License
