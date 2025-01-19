# FCG Extractor

A Python package for extracting function call graphs andthe instructions of each function from executable files using radare2.

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
extractor = ExtractFeature()

# Prepare input DataFrame
df_input = pd.DataFrame({
    'file_name': ['sample1.exe', 'sample2.exe']
})

# Extract features
extractor.process_features(
    feature='feature_to_extract',
    df_input=df_input,
    dir_feature='output/features',
    dir_dataset='samples/dataset',
    timeout_seconds=300,
    dir_log='logs'
)
```

## Features

- Extracts features (function call graphs & opcodes) from both standard ELF files and compressed/packed executables
- Handles timeouts gracefully
- Parallel processing for better performance
- Comprehensive logging
- Dependency checking

## License

MIT License
