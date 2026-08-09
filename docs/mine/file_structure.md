Here is the complete, production-grade project file structure for **Project #4: `guardrail-cpp`** (*Sub-Millisecond Native Prompt Injection & Memory Shield in C++*).

This project addresses the major limitation of Python-based guardrails (which add 50ms–200ms latency to every request). `guardrail-cpp` is built in **native C++20 and CUDA** to perform sub-millisecond (<0.5ms) token sanitization, system prompt firewalling, indirect prompt injection detection, and canary token leak prevention directly at the inference node layer (vLLM, TensorRT-LLM, LibTorch).

---

### Project File Structure: `guardrail-cpp`

```
guardrail-cpp/
├── README.md                          # Production-grade GitHub overview & latency benchmarks
├── LICENSE                            # Apache 2.0 License
├── CMakeLists.txt                     # C++20 & CUDA CMake build configuration
├── .clang-format                      # LLVM C++/CUDA coding style
├── .gitignore                         # Ignores build artifacts, compiled rule indexes, test logs
│
├── cmake/                             # CMake Modules & Dependency Finders
│   ├── FindHyperscan.cmake            # Find script for Intel Hyperscan / Vectorscan (SIMD regex)
│   ├── FindOpenSSL.cmake              # OpenSSL 3.x find script
│   └── CUDAUtils.cmake                # CUDA compiler flags & architecture setup
│
├── include/guardrail/                 # Public C++20 / CUDA Headers
│   ├── guardrail.hpp                  # Master header, version macros, & error status codes
│   │
│   ├── sanitizer/                     # Sub-Millisecond String & Token Sanitizers
│   │   ├── token_sanitizer.hpp        # Fast C++20 zero-copy token/string sanitizer
│   │   ├── aho_corasick_matcher.hpp   # High-throughput multi-pattern Aho-Corasick matcher
│   │   └── unicode_normalizer.hpp     # Unicode homoglyph & zero-width space normalizer
│   │
│   ├── detectors/                     # Security Threat Detectors
│   │   ├── prompt_injection_detector.hpp  # Indirect prompt injection & system override detector
│   │   ├── canary_token_detector.hpp      # System prompt leak & PII exfiltration detector
│   │   └── toxic_content_detector.hpp     # SIMD-accelerated toxicity & keyword classifier
│   │
│   ├── cuda/                          # GPU Parallel Pattern Matching
│   │   └── cuda_pattern_matcher.hpp   # CUDA host/device interface for batch prompt scanning
│   │
│   └── policy/                        # Guardrail Rule Policies
│       └── guardrail_policy.hpp       # YAML/JSON policy loader, thresholds, & action engine
│
├── src/                               # C++ Implementation Files
│   ├── sanitizer/
│   │   ├── token_sanitizer.cpp
│   │   ├── aho_corasick_matcher.cpp
│   │   └── unicode_normalizer.cpp
│   ├── detectors/
│   │   ├── prompt_injection_detector.cpp
│   │   ├── canary_token_detector.cpp
│   │   └── toxic_content_detector.cpp
│   └── policy/
│       └── guardrail_policy.cpp
│
├── cuda/                              # Custom CUDA Device Kernels (.cu)
│   └── cuda_pattern_matcher.cu        # High-throughput CUDA kernel for batch prompt inspection
│
├── cmd/                               # Executable Entrypoints
│   └── guardrail-cli/                 # Terminal Inspection & Benchmarking Tool
│       └── main.cpp                   # Inspects prompts, measures latency, evaluates policies
│
├── rules/                             # Pre-Configured Rule Dictionaries & Policies
│   ├── strict_guardrails.yaml         # Production security policy rules
│   ├── jailbreak_patterns.json        # Compiled Aho-Corasick dictionary for known jailbreaks
│   └── canary_tokens.json             # Registry of active system prompt canary tokens
│
├── scripts/                           # Benchmarking & Rule Compilation Scripts
│   ├── benchmark_latency.py           # Measures C++ guardrail latency vs. Python guardrails
│   └── update_jailbreak_rules.py      # Fetches & compiles latest OWASP LLM Top 10 patterns
│
└── tests/                             # Unit & Security Performance Tests
    ├── CMakeLists.txt
    ├── test_prompt_injection.cpp      # Unit tests for indirect prompt injection detection
    ├── test_token_sanitizer.cpp       # Tests sub-millisecond string normalization
    └── test_cuda_matcher.cpp          # Tests GPU batch pattern matching throughput
```

---

### Module Interaction Overview

```
 [ Incoming User Prompt / Agent RAG Input ]
                     |
                     v
   +-------------------------------------------------------------+
   | guardrail-cpp C++20 Core Engine                             |
   |                                                             |
   | 1. Unicode Normalizer (unicode_normalizer.cpp)             |
   |    - Removes zero-width characters & homoglyph obfuscation  |
   |                                                             |
   | 2. Aho-Corasick / SIMD Matcher (aho_corasick_matcher.cpp)   |
   |    - Sub-millisecond scan across 10,000+ jailbreak rules    |
   |                                                             |
   | 3. Prompt Injection Detector (prompt_injection_detector.cpp)|
   |    - Detects system prompt overrides & role-play exploits   |
   |                                                             |
   | 4. CUDA Batch Inspector (cuda/cuda_pattern_matcher.cu)      |
   |    - Parallel GPU token inspection for batch LLM queries   |
   +-------------------------------------------------------------+
                     |
         +-----------+-----------+
         |                       |
         v (CLEAN)               v (ATTACK DETECTED)
 [ Allowed to CUDA ]      [ BLOCK / SANITIZE / LOG ]
 [ Inference Engine ]     [ Trigger Security Alert ]
```

---

### Key Technical Highlights of `guardrail-cpp`

1. **Sub-Millisecond Execution SLA:** Delivers <0.4ms inspection latency per query by avoiding Python GIL overheads and heavy neural network calls during input validation.
2. **Aho-Corasick & SIMD Matching:** Evaluates incoming prompt buffers against 10,000+ known jailbreak signatures in a single linear pass ($O(N)$ string length complexity).
3. **Unicode Homoglyph Normalization:** Strips zero-width spaces, invisible characters, and Cyrillic/Greek homoglyphs used by attackers to bypass string-matching filters.
4. **Batch GPU Pattern Scanning:** Includes custom CUDA kernels (`cuda/cuda_pattern_matcher.cu`) to scan multi-tenant batch inference prompt queues directly on NVIDIA GPUs.