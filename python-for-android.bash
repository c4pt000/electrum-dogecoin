cd /opt \
    && git clone https://github.com/kivy/python-for-android \
    && cd python-for-android \
    && git remote add sombernight https://github.com/SomberNight/python-for-android \
    && git fetch --all \
    && git checkout "cdee188f0ef28ff8452207da409912da19e917ca^{commit}" \
    && python3 -m pip install --no-dependencies --user -e .

