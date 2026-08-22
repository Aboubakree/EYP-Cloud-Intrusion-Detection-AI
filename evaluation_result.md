==========================================================================
  PER-ATTACK EVALUATION : CICIDS-2017 model vs our own lab traffic
==========================================================================
  Model   : detector_rf.joblib  (Random Forest)
  Features: 49
  Source  : experimental_attack

  Processing Benign traffic     (0 MB)...
      → 21 flows, 0 flagged (0.00%), 0.2s

  Processing SSH brute force    (0 MB)...
      → 6 flows, 4 flagged (66.67%), 0.2s

  Processing Port scan          (25 MB)...
      → 65,537 flows, 0 flagged (0.00%), 0.5s

  Processing SYN flood (DoS)    (672 MB)...
      → 1,523,389 flows, 0 flagged (0.00%), 9.6s

==========================================================================
  RESULTS TABLE
==========================================================================
   Traffic type Ground truth     Flows Flagged attack  Rate %  Mean proba  Max proba  Dropped
 Benign traffic       benign        21              0    0.00       0.148      0.160        0
SSH brute force       attack         6              4   66.67       0.488      0.695        0
      Port scan       attack    65,537              0    0.00       0.000      0.270        0
SYN flood (DoS)       attack 1,523,389              0    0.00       0.058      0.150        0

==========================================================================
  READING THE TABLE
==========================================================================
  Benign traffic     → 0.00% flagged = FALSE POSITIVE RATE (lower is better)
  SSH brute force    → 66.67% detected = PARTIALLY detected : weak transfer
  Port scan          → 0.00% detected = MISSED : the generalization gap
  SYN flood (DoS)    → 0.00% detected = MISSED : the generalization gap

==========================================================================
  Saved: /mnt/lab-project/ids-project/reports/results/per_attack_results.csv
  Saved: /mnt/lab-project/ids-project/reports/results/per_attack_results.tex
==========================================================================
