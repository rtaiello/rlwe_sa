# Secure Aggregation with Ring LWE

## Description

This repository contains a Python implementation of the RLWE-SA protocol, as proposed in [ACORN: Input Validation for Secure Aggregation](https://eprint.iacr.org/2022/1461.pdf) (Section 3.2). The implementation is built upon the [Google Shell Encryption library](https://github.com/google/shell-encryption).

---

## Technical Details

This project implements the **Hint-RLWE reduction**, with a ciphertext modulus of 80 bits. The samples consist of standard RLWE pairs \((a, as + e)\) along with a “hint” \((e + f)\), where \(f\) is sampled from the same discrete Gaussian distribution as \(e\). The Gaussian distribution is defined over the interval \([-32, +32]\) with a standard deviation (\(\sigma\)) of 4.5, used for generating errors (\(e, f\)) and the secret key.

The secret key is converted in Python to fit within a 14-bit interval. This configuration assumes the sum over the key allows for the aggregation of approximately 256 ciphertexts.

Currently, the gadget matrix, which packs input messages into ciphertext slots, is implemented using the vector encoding proposed by [FTSA](https://github.com/MohamadMansouri/fault-tolerant-secure-agg).

The parameters used ensure at least **155 bits of security**, following the guidelines of the [Lattice Estimator](https://github.com/malb/lattice-estimator).

---

## Dependencies

To run the code, you'll need a working Python environment. We recommend using the [Anaconda Python distribution](https://www.anaconda.com/products/distribution), which provides the `conda` package manager. Anaconda can be installed in your user directory and does not interfere with your system Python installation.

### Additional Configuration

- Configure [Bazel](https://bazel.build) as per the requirements of the [Google Shell Encryption library](https://github.com/google/shell-encryption).

---

## Setup Instructions

1. Clone the repository:  
   ```bash
   git clone https://github.com/rtaiello/rlwe_sa
   ```

2. Create the environment:  
   ```bash
   conda create -n rlwe-sa python=3.8
   ```

3. Activate the environment:  
   ```bash
   conda activate rlwe-sa
   ```

4. Install the dependencies:  
   ```bash
   python setup.py install
   ```

---

## Running the Code 🚀

To run the code, refer to the [Jupyter Notebook example](https://github.com/rtaiello/rlwe_sa/blob/main/test_nb/test.ipynb).

---

## Code Contributions

- **FTSA Repository**: [Fault-Tolerant Secure Aggregation](https://github.com/MohamadMansouri/fault-tolerant-secure-agg)  
- **Google Shell Repository**: [Google Shell Encryption](https://github.com/google/shell-encryption)

