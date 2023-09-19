"""
Entrypoint for flask run.
"""
import zeek_benchmarker.app
import zeek_benchmarker.config

cfg = zeek_benchmarker.config.get()
app = zeek_benchmarker.app.create_app(
    config={
        "HMAC_KEY": cfg["HMAC_KEY"],
        "ALLOWED_BUILD_URLS": cfg["ALLOWED_BUILD_URLS"],
        "DATABASE_FILE": cfg["DATABASE_FILE"],
    }
)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=False)
