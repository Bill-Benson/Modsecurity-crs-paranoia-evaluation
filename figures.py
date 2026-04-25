import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import csv
import os

PL1_RESULTS = r'logs\pl1\results_FINAL_pl1.csv'   
PL2_RESULTS = r'logs\pl2\results_FINAL_pl2.csv'
OUTPUT_DIR  = r'figures_output'           

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Global style ──────────────────────────────────────────────────────────
plt.rcParams.update({
    'font.family':       'DejaVu Sans',
    'font.size':         11,
    'axes.titlesize':    13,
    'axes.titleweight':  'bold',
    'axes.labelsize':    11,
    'axes.spines.top':   False,
    'axes.spines.right': False,
    'axes.grid':         True,
    'axes.grid.axis':    'y',
    'grid.alpha':        0.3,
    'grid.linestyle':    '--',
    'figure.dpi':        300,
    'savefig.dpi':       300,
    'savefig.bbox':      'tight',
    'savefig.facecolor': 'white',
})

PL1_COL   = '#2E86AB'
PL2_COL   = '#E84855'
SQLI_COL  = '#2E86AB'
XSS_COL   = '#E84855'
PROTO_COL = '#6C757D'


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 3 -- Benign Traffic Composition
# ══════════════════════════════════════════════════════════════════════════
def figure3():
    categories = ['Neutral', 'SQL-Keyword', 'Special-Chars', 'Scripting-Keyword']
    counts     = [252, 129, 71, 48]
    percents   = [f'{c/500*100:.1f}%' for c in counts]
    colors     = ['#4CAF50', '#2E86AB', '#FF9800', '#E84855']

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(categories, counts, color=colors, alpha=0.9,
                   edgecolor='white', linewidth=1.2, zorder=3)

    # Count + percentage labels at end of each bar
    for bar, count, pct in zip(bars, counts, percents):
        ax.text(bar.get_width() + 3, bar.get_y() + bar.get_height() / 2,
                f'{count} ({pct})', va='center', ha='left',
                fontsize=10, fontweight='bold')

    ax.set_xlabel('Number of Requests')
    ax.set_xlim(0, 310)
    ax.set_title('Figure 3: Benign Traffic Set Composition (n = 500)\n'
                 'Neutral majority reflects realistic e-commerce traffic distribution')
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.grid(axis='y', alpha=0)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure3_benign_composition.png'))
    plt.close()
    print('Figure 3 saved.')


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 5 -- Headline Metrics Bar Chart
# ══════════════════════════════════════════════════════════════════════════
def figure5():
    metrics  = ['TPR', 'FPR', 'Precision', 'Specificity', 'F1', 'MCC*']
    pl1_vals = [97.0,  1.0,   97.5,        99.0,          97.2, 96.14]
    pl2_vals = [97.0,  2.0,   95.1,        98.0,          96.0, 94.44]

    x, w = np.arange(len(metrics)), 0.35

    fig, ax = plt.subplots(figsize=(11, 6))
    b1 = ax.bar(x - w/2, pl1_vals, w, label='PL1', color=PL1_COL, alpha=0.9, zorder=3)
    b2 = ax.bar(x + w/2, pl2_vals, w, label='PL2', color=PL2_COL, alpha=0.9, zorder=3)

    for bar, col in [(b, PL1_COL) for b in b1] + [(b, PL2_COL) for b in b2]:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 0.4,
                f'{h:.1f}%', ha='center', va='bottom',
                fontsize=8.5, fontweight='bold', color=col)

    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_ylabel('Score (%)')
    ax.set_ylim(0, 108)
    ax.set_title('Figure 5: Headline Performance Metrics — PL1 vs PL2')
    ax.legend(loc='lower right', framealpha=0.9)

    # MCC footnote below the x-axis, well clear of bars
    fig.text(0.5, -0.02,
             '* MCC values scaled ×100 for display. Raw values: PL1 = 0.9614, PL2 = 0.9444',
             ha='center', fontsize=8.5, color='#555555', style='italic')

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure5_headline_metrics.png'))
    plt.close()
    print('Figure 5 saved.')


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 6 -- Subcategory Detection Rate
# ══════════════════════════════════════════════════════════════════════════
def figure6():
    subcats = ['SQLi\nBasic', 'SQLi\nBoolean', 'SQLi\nUnion', 'SQLi\nTime-Based',
               'SQLi\nObfuscated', 'XSS\nBasic', 'XSS\nEvent-Based',
               'XSS\nMixed-Evasion', 'XSS\nObfuscated', 'XSS\nAdvanced']
    rates   = [95.0, 90.0, 100.0, 100.0, 90.0,
               100.0, 100.0, 100.0, 95.0, 100.0]

    x, w = np.arange(len(subcats)), 0.35

    fig, ax = plt.subplots(figsize=(14, 6))
    b1 = ax.bar(x - w/2, rates, w, label='PL1', color=PL1_COL, alpha=0.9, zorder=3)
    b2 = ax.bar(x + w/2, rates, w, label='PL2', color=PL2_COL, alpha=0.9, zorder=3)

    for bar in list(b1) + list(b2):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 0.2,
                f'{h:.0f}%', ha='center', va='bottom', fontsize=8)

    ax.axvline(x=4.5, color='#AAAAAA', linestyle=':', linewidth=1.5, zorder=2)
    ax.text(2.0, 80.5, 'SQLi', ha='center', fontsize=11, color='#555555', style='italic')
    ax.text(7.0, 80.5, 'XSS',  ha='center', fontsize=11, color='#555555', style='italic')
    ax.axhline(y=90, color='#FF9800', linestyle='--', linewidth=1.2, alpha=0.7, zorder=1)
    ax.text(9.75, 90.4, '90% floor', fontsize=8, color='#FF9800', ha='right')

    ax.set_xticks(x)
    ax.set_xticklabels(subcats, fontsize=9)
    ax.set_ylabel('Detection Rate (%)')
    ax.set_ylim(78, 110)
    ax.set_title('Figure 6: Detection Rate by Attack Subcategory — PL1 vs PL2\n'
                 '(Rates are identical across both configurations for all subcategories)')
    ax.legend(loc='lower right', framealpha=0.9)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure6_subcategory_detection.png'))
    plt.close()
    print('Figure 6 saved.')


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 7 -- Top Rules Firing Frequency
# ══════════════════════════════════════════════════════════════════════════
def figure7():
    rules_data = [
        ('942100 – SQL Injection via libinjection',     97, SQLI_COL),
        ('941100 – XSS via libinjection',               92, XSS_COL),
        ('941160 – NoScript XSS HTML Injection',        85, XSS_COL),
        ('941120 – XSS Event Handler Vector',           50, XSS_COL),
        ('941110 – XSS Script Tag Vector',              30, XSS_COL),
        ('942360 – Concatenated SQLi/SQLLFI',           27, SQLI_COL),
        ('942190 – MSSQL Code Execution',               25, SQLI_COL),
        ('941140 – Javascript URI Vector',              23, XSS_COL),
        ('942160 – Blind SQLi sleep()/benchmark()',     17, SQLI_COL),
        ('941210 – IE XSS Filters',                     15, XSS_COL),
        ('941170 – NoScript XSS Attribute Injection',   14, XSS_COL),
        ('932115 – Windows Command Injection',           8, PROTO_COL),
        ('942140 – Common DB Names Detected',            8, SQLI_COL),
        ('942270 – Basic SQLi Common Strings',           8, SQLI_COL),
        ('942230 – Conditional SQLi Attempts',           6, SQLI_COL),
    ]

    labels_r = [r[0] for r in rules_data]
    fires    = [r[1] for r in rules_data]
    colors_r = [r[2] for r in rules_data]

    y, h = np.arange(len(labels_r)), 0.6

    fig, ax = plt.subplots(figsize=(13, 9))
    ax.barh(y, fires, h, color=colors_r, alpha=0.88, zorder=3)

    # Value labels at end of each bar
    for i, v in enumerate(fires):
        ax.text(v + 0.5, i, str(v), va='center', fontsize=9, fontweight='bold')

    ax.set_yticks(y)
    ax.set_yticklabels(labels_r, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel('Number of Times Fired')
    ax.set_xlim(0, 115)
    ax.set_title('Figure 7: Top 15 CRS Rules by Fire Count — PL1 vs PL2\n'
                 'All rules tagged paranoia-level/1; fire counts identical across both configurations')
    ax.grid(axis='x', alpha=0.3, linestyle='--')
    ax.grid(axis='y', alpha=0)

    sqli_patch  = mpatches.Patch(color=SQLI_COL,  label='SQLi rules (942xxx)')
    xss_patch   = mpatches.Patch(color=XSS_COL,   label='XSS rules (941xxx)')
    proto_patch = mpatches.Patch(color=PROTO_COL,  label='Protocol/RCE rules')
    ax.legend(handles=[sqli_patch, xss_patch, proto_patch],
              loc='lower right', fontsize=9, framealpha=0.9)

    # Note at bottom of figure, below axes
    fig.text(0.5, -0.01,
             'Note: PL1 and PL2 fire counts are identical for all rules shown. '
             'Rule 920220 (URL Encoding Abuse) not in top 15: PL1 = 1 fire, PL2 = 6 fires.',
             ha='center', fontsize=8.5, color='#555555', style='italic')

    # Remove PL1/PL2 paired bar approach -- counts are identical so one bar per rule is correct
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure7_rule_frequency.png'))
    plt.close()
    print('Figure 7 saved.')


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 8 -- Anomaly Score Distribution
# ══════════════════════════════════════════════════════════════════════════
def figure8():
    scores = [3,  5,  8,  10, 15, 20, 25, 30, 35]
    counts = [5, 54,  1,  22, 76, 23, 14,  6,  3]

    bar_colors = ['#FF9800' if s <= 3 else PL1_COL for s in scores]

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(scores, counts, width=2.2, color=bar_colors, alpha=0.9,
                  edgecolor='white', linewidth=1.5, zorder=3)

    # Threshold lines
    ax.axvline(x=3, color=PL2_COL, linestyle='--', linewidth=2, zorder=4,
               label='PL2 inbound threshold (score 3)')
    ax.axvline(x=5, color=PL1_COL, linestyle='--', linewidth=2, zorder=4,
               label='PL1 inbound threshold (score 5)')

    # Shaded zone between thresholds
    ax.axvspan(3, 5, alpha=0.07, color='#FF9800', zorder=2)

    # Value labels on bars
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.8,
                str(count), ha='center', va='bottom', fontsize=9.5, fontweight='bold')

    # Annotation for the zone -- placed upper right, well away from bars
    ax.annotate(
        'PL2 blocks, PL1 allows\n(n=5, score=3=PL2 threshold)',
        xy=(3, 5), xytext=(12, 62),
        fontsize=9, color='#CC6600',
        arrowprops=dict(arrowstyle='->', color='#CC6600', lw=1.2),
        bbox=dict(boxstyle='round,pad=0.4', facecolor='#FFF3E0',
                  edgecolor='#FF9800', alpha=0.95)
    )

    # Annotation for score 15 peak -- placed to the right
    ax.annotate(
        'Peak: 76 requests\n(3-rule co-fires:\nlibinjection + category\n+ HTML injection)',
        xy=(15, 76), xytext=(22, 65),
        fontsize=8.5, color='#333333',
        arrowprops=dict(arrowstyle='->', color='#555555', lw=1.2),
        bbox=dict(boxstyle='round,pad=0.4', facecolor='white',
                  edgecolor='#AAAAAA', alpha=0.9)
    )

    ax.set_xlabel('Inbound Anomaly Score')
    ax.set_ylabel('Number of Requests Blocked')
    ax.set_xticks(scores)
    ax.set_ylim(0, 95)
    ax.set_title('Figure 8: Anomaly Score Distribution of All Blocked Requests\n'
                 '(Orange bar = PL2-exclusive false positives; dashed lines = blocking thresholds)')
    ax.legend(loc='upper right', framealpha=0.9, fontsize=9)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure8_anomaly_distribution.png'))
    plt.close()
    print('Figure 8 saved.')


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 9 -- Attack Complexity vs Anomaly Score Scatter
# ══════════════════════════════════════════════════════════════════════════
def figure9():
    # Only detected payloads have scores. 6 bypasses scored 0 and are excluded.
    subcat_scores = {
        'SQLi\nBasic':        [5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,10],
        'SQLi\nBoolean':      [5,5,5,5,5,5,5,5,5,5,5,5,5,5,8,10,15,15],
        'SQLi\nTime-Based':   [10,10,10,10,10,10,10,10,15,15,15,15,15,20,20,20,25,30,35,35],
        'SQLi\nUnion':        [15,15,15,15,15,15,15,15,15,15,15,20,20,25,25,25,25,25,25,25],
        'SQLi\nObfuscated':   [5,5,5,5,5,5,5,5,5,5,5,5,5,5,10,10,10,15],
        'XSS\nBasic':         [10,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,15,20,20,25],
        'XSS\nEvent-Based':   [10,10,15,15,15,15,15,15,15,15,15,15,15,15,15,15,20,20,20,20],
        'XSS\nMixed-Evasion': [5,10,10,10,15,15,15,15,15,15,15,20,20,20,20,30,30,30,30,35],
        'XSS\nObfuscated':    [5,5,10,15,15,15,15,15,15,15,15,15,15,15,20,20,20,25,25],
        'XSS\nAdvanced':      [10,10,15,15,15,15,15,15,15,15,15,20,20,20,20,20,25,25,25,30],
    }

    keys = list(subcat_scores.keys())
    fig, ax = plt.subplots(figsize=(14, 7))
    np.random.seed(42)
    jitter = 0.18

    for i, (subcat, sc_list) in enumerate(subcat_scores.items()):
        color = SQLI_COL if 'SQLi' in subcat else XSS_COL
        jx    = i + np.random.uniform(-jitter, jitter, len(sc_list))
        ax.scatter(jx, sc_list, color=color, alpha=0.5, s=50, zorder=3)
        mean_s = np.mean(sc_list)
        ax.hlines(mean_s, i - 0.32, i + 0.32, colors=color, linewidth=2.8, zorder=4)
        # Mean label above the line, offset to avoid overlap
        ax.text(i, mean_s + 1.0, f'{mean_s:.1f}',
                ha='center', va='bottom', fontsize=8.5,
                color=color, fontweight='bold')

    # SQLi / XSS divider
    ax.axvline(x=4.5, color='#AAAAAA', linestyle=':', linewidth=1.5)
    ax.text(2.2, 38.5, 'SQLi', ha='center', fontsize=11,
            color='#555555', style='italic')
    ax.text(7.2, 38.5, 'XSS',  ha='center', fontsize=11,
            color='#555555', style='italic')

    ax.set_xticks(range(len(keys)))
    ax.set_xticklabels(keys, fontsize=9)
    ax.set_ylabel('Inbound Anomaly Score')
    ax.set_ylim(0, 43)
    ax.set_title('Figure 9: Anomaly Score Distribution by Attack Subcategory\n'
                 'Horizontal bars = subcategory mean  |  Points = individual detected payloads  |'
                 '  6 bypasses excluded (zero score)')

    sqli_patch = mpatches.Patch(color=SQLI_COL, label='SQLi subcategories')
    xss_patch  = mpatches.Patch(color=XSS_COL,  label='XSS subcategories')
    ax.legend(handles=[sqli_patch, xss_patch], loc='upper left', framealpha=0.9)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure9_complexity_scatter.png'))
    plt.close()
    print('Figure 9 saved.')


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 10 -- FP Breakdown by Benign Subcategory
# ══════════════════════════════════════════════════════════════════════════
def figure10():
    benign_cats = ['SQL-Keyword\n(n=129)', 'Scripting-Keyword\n(n=48)',
                   'Special-Chars\n(n=71)', 'Neutral\n(n=252)']
    pl1_fpr = [1.55, 6.25, 0.00, 0.00]
    pl2_fpr = [1.55, 6.25, 7.04, 0.00]

    x, w = np.arange(len(benign_cats)), 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    b1 = ax.bar(x - w/2, pl1_fpr, w, label='PL1', color=PL1_COL, alpha=0.9, zorder=3)
    b2 = ax.bar(x + w/2, pl2_fpr, w, label='PL2', color=PL2_COL, alpha=0.9, zorder=3)

    for bar in list(b1) + list(b2):
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.12,
                    f'{h:.2f}%', ha='center', va='bottom',
                    fontsize=9, fontweight='bold')
        else:
            ax.text(bar.get_x() + bar.get_width() / 2, 0.12,
                    '0.00%', ha='center', va='bottom',
                    fontsize=8, color='#999999')

    # Annotate the key PL2 Special-Chars finding
    ax.annotate(
        '0.00% → 7.04%\nRule 920220 (score 3)\n= exact PL2 threshold',
        xy=(2 + w/2, 7.04), xytext=(2.85, 5.8),
        fontsize=8.5, color=PL2_COL,
        arrowprops=dict(arrowstyle='->', color=PL2_COL, lw=1.2),
        bbox=dict(boxstyle='round,pad=0.35', facecolor='white',
                  edgecolor=PL2_COL, alpha=0.9)
    )

    ax.set_xticks(x)
    ax.set_xticklabels(benign_cats)
    ax.set_ylabel('False Positive Rate (%)')
    ax.set_ylim(0, 10.5)
    ax.set_title('Figure 10: False Positive Rate by Benign Traffic Subcategory — PL1 vs PL2\n'
                 'Special-Chars divergence driven entirely by rule 920220 at the PL2 anomaly threshold')
    ax.legend(loc='upper left', framealpha=0.9)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure10_fp_subcategory.png'))
    plt.close()
    print('Figure 10 saved.')


# ══════════════════════════════════════════════════════════════════════════
# FIGURE 11 -- Latency Box Plot
# ══════════════════════════════════════════════════════════════════════════
def figure11():
    pl1_atk, pl1_ben, pl2_atk, pl2_ben = [], [], [], []

    with open(PL1_RESULTS) as f:
        for row in csv.DictReader(f):
            lat = float(row['Latency_ms'])
            (pl1_ben if row['Category'] == 'Benign' else pl1_atk).append(lat)

    with open(PL2_RESULTS) as f:
        for row in csv.DictReader(f):
            lat = float(row['Latency_ms'])
            (pl2_ben if row['Category'] == 'Benign' else pl2_atk).append(lat)

    data       = [pl1_atk, pl2_atk, pl1_ben, pl2_ben]
    labels_bp  = ['PL1\nAttack\n(n=200)', 'PL2\nAttack\n(n=200)',
                  'PL1\nBenign\n(n=500)', 'PL2\nBenign\n(n=500)']
    colors_bp  = [PL1_COL, PL2_COL, PL1_COL, PL2_COL]

    fig, ax = plt.subplots(figsize=(10, 6))
    bp = ax.boxplot(
        data, patch_artist=True, notch=False,
        medianprops=dict(color='white', linewidth=2.5),
        whiskerprops=dict(linewidth=1.5),
        capprops=dict(linewidth=1.5),
        flierprops=dict(marker='o', markersize=3, alpha=0.35, markeredgewidth=0)
    )
    for patch, color in zip(bp['boxes'], colors_bp):
        patch.set_facecolor(color)
        patch.set_alpha(0.8)

    # Median labels -- placed ABOVE each box to avoid overlap
    for i, d in enumerate(data):
        med = np.median(d)
        q75 = np.percentile(d, 75)
        ax.text(i + 1, q75 + 1.5, f'Med: {med:.1f}ms',
                ha='center', va='bottom', fontsize=8.5,
                color='#333333', fontweight='bold')

    # Divider between attack and benign groups
    ax.axvline(x=2.5, color='#AAAAAA', linestyle=':', linewidth=1.5)
    ax.text(1.5, ax.get_ylim()[1] * 0.95, 'Attack Traffic',
            ha='center', fontsize=10, color='#555555', style='italic')
    ax.text(3.5, ax.get_ylim()[1] * 0.95, 'Benign Traffic',
            ha='center', fontsize=10, color='#555555', style='italic')

    ax.set_xticks(range(1, 5))
    ax.set_xticklabels(labels_bp, fontsize=10)
    ax.set_ylabel('Response Latency (ms)')
    ax.set_title('Figure 11: Response Latency Distribution — PL1 vs PL2 by Traffic Type\n'
                 'Overlapping interquartile ranges confirm no meaningful latency difference between configurations')

    pl1_patch = mpatches.Patch(color=PL1_COL, alpha=0.8, label='PL1')
    pl2_patch = mpatches.Patch(color=PL2_COL, alpha=0.8, label='PL2')
    ax.legend(handles=[pl1_patch, pl2_patch], loc='upper right', framealpha=0.9)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.grid(axis='x', alpha=0)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, 'figure11_latency_boxplot.png'))
    plt.close()
    print('Figure 11 saved.')


# ── Run all ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    figure3()
    figure5()
    figure6()
    figure7()
    figure8()
    figure9()
    figure10()
    figure11()
    print(f'\nAll figures saved to: {OUTPUT_DIR}')
