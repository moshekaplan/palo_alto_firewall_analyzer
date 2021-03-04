import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="palo_alto_firewall_analyzer",
    version="0.0.1",
    author="Moshe Kaplan",
    author_email="me@moshekaplan.com",
    description="Detect and remediate configuration issues in Palo Alto Networks firewalls",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/moshekaplan/palo_alto_firewall_analyzer",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Topic :: System :: Networking :: Firewalls",
        
    ],
    python_requires='>=3.7',
)
