"""Static PNG report with Matplotlib (for emailing or attaching to a ticket),
complementing the interactive Plotly dashboard."""
import matplotlib
matplotlib.use("Agg")  # draw to a file, no window needed
import matplotlib.pyplot as plt

from .stats import Z_THRESHOLD, traffic_zscores


def save_report(df, alerts_df, path: str) -> str:
    z = traffic_zscores(df)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 7), sharex=True)

    ax1.bar(z.index, z.failures, width=0.035, color="#94a3b8", label="failed logins / hour")
    spikes = z[z.anomaly]
    ax1.scatter(spikes.index, spikes.failures, color="#b91c1c", marker="x", s=80, zorder=3,
                label="anomaly")
    ax1.set_ylabel("failed logins")
    ax1.legend(loc="upper right", frameon=False)
    ax1.set_title(f"CyberSentinel report: {len(df):,} events, {len(alerts_df)} alerts")

    ax2.plot(z.index, z.z_failures, color="#1d4ed8", linewidth=1.2)
    ax2.axhline(Z_THRESHOLD, color="#b91c1c", linestyle="--", linewidth=1,
                label=f"threshold z={Z_THRESHOLD:g}")
    ax2.set_ylabel("z-score")
    ax2.legend(loc="upper right", frameon=False)

    for ax in (ax1, ax2):
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.3)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path
