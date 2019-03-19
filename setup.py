import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="securecscc",
    version="2.0.0",
    author="Néstor Salceda",
    author_email="nestor.salceda@sysdig.com",
    description="Kubernetes security for Google Cloud Security Command Center.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/draios/sysdig-gcscc-connector",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Plugins",
        "Framework :: Flask",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
