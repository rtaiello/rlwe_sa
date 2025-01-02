# Secure Aggregation with Hint-RLWE

This library provides a user-friendly Python API for secure aggregation based on Hint-RLWE, leveraging [Google's Shell Encryption library](https://github.com/google/shell-encryption). It implements parts of the Ring LWE and encryption scheme detailed in the paper [ACORN: Input Validation for Secure Aggregation](https://eprint.iacr.org/2022/1461).

---

## Features

- **Secure Aggregation API**: Implements cryptographic primitives for secure data aggregation.
- **Based on RLWE**: Leverages Ring Learning with Errors (RLWE) for strong cryptographic guarantees.
- **Federated Learning Support**: Suitable for privacy-preserving data aggregation in federated learning.
- **Integration with Shell Encryption**: Built using Google's Shell Encryption library for high performance and scalability.

---

## Prerequisites

- Python 3.8
- [Anaconda Python Distribution](https://www.anaconda.com/products/distribution) (recommended for managing dependencies)
- [Google's Shell Encryption library](https://github.com/google/shell-encryption) (installed and configured as a dependency)

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/rtaiello/rlwe_sa.git
   cd rlwe_sa
   ```

2. Set up the environment using Anaconda:
   ```bash
   conda create -n rlwe-sa python=3.8
   conda activate rlwe-sa
   ```

3. Install the library:
   ```bash
   python setup.py install
   ```

---

## Usage

You can find an example usage of the library in this [Jupyter Notebook](https://github.com/rtaiello/rlwe_sa/blob/main/test_nb/test.ipynb).



---

## Technical Details

The library fixes parameters used in [1], ensuring consistency with the theoretical guarantees. Key technical details:

- **Error Vectors**: Error vectors e and f are sampled using discrete Gaussian distribution with sigma = 4.5.
- **Ciphertext Modulus**: The ciphertext modulus is set to q = 80 bits, achieving 155-bit security as simulated with the [lattice-estimator](https://github.com/malb/lattice-estimator).
- **Input Encoding**: The input encoding (gadget matrix) is implemented based on the techniques described in [2].

---

## Acknowledgments

- **Contributors**:
  - FTSA repository ([GitHub](https://github.com/MohamadMansouri/fault-tolerant-secure-agg))
  - Google's Shell Encryption library ([GitHub](https://github.com/google/shell-encryption))

---

## References

1. [ACORN: Input Validation for Secure Aggregation](https://eprint.iacr.org/2022/1461.pdf)
2. [Learning from Failures: Secure and Fault-Tolerant Aggregation for Federated Learning](https://dl.acm.org/doi/pdf/10.1145/3564625.3568135)

---

## License

This library is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

---

## Contact

For questions or support, open an issue or contact the author at `<your-email@example.com>`. Feedback and contributions are appreciated!

