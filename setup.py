from setuptools import setup,find_packages
setup(name="kerberoast",version="2.0.0",author="bad-antics",description="Kerberoasting attack simulation and detection",packages=find_packages(where="src"),package_dir={"":"src"},python_requires=">=3.8")
