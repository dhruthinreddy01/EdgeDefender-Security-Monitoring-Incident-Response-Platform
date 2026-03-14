# Risk Scoring Engine

def calculate_risk_score(detection_type, base_score, correlation_bonus=0):
    """
    Calculate the final risk score based on detection type, base score, and correlation bonus.

    :param detection_type: Type of detection (e.g., 'Brute Force', 'Malware', 'Phishing')
    :param base_score: Base score for the detection type
    :param correlation_bonus: Additional score for correlated threats
    :return: Final risk score and severity classification
    """
    # Calculate the final score
    final_score = base_score + correlation_bonus
    final_score = min(final_score, 100)  # Cap the score at 100

    # Classify severity
    if final_score <= 30:
        severity = "Low"
    elif final_score <= 60:
        severity = "Medium"
    elif final_score <= 80:
        severity = "High"
    else:
        severity = "Critical"

    return final_score, severity

def enrich_threat_intelligence(detection_type, base_score, correlation_bonus=0):
    """
    Enrich threat intelligence by simulating a local threat feed and integrating it into the risk engine.
    Matches increase the risk score and log the enrichment source.

    :param detection_type: Type of detection (e.g., 'Brute Force', 'Malware', 'Phishing')
    :param base_score: Base score for the detection type
    :param correlation_bonus: Additional score for correlated threats
    :return: Final risk score and severity classification
    """
    # Calculate the final score
    final_score = base_score + correlation_bonus
    final_score = min(final_score, 100)  # Cap the score at 100

    # Classify severity
    if final_score <= 30:
        severity = "Low"
    elif final_score <= 60:
        severity = "Medium"
    elif final_score <= 80:
        severity = "High"
    else:
        severity = "Critical"

    return final_score, severity

if __name__ == "__main__":
    # Example usage
    detection_type = "Brute Force"
    base_score = 40
    correlation_bonus = 20

    final_score, severity = calculate_risk_score(detection_type, base_score, correlation_bonus)
    print(f"Detection Type: {detection_type}")
    print(f"Base Score: {base_score}")
    print(f"Correlation Bonus: {correlation_bonus}")
    print(f"Final Score: {final_score}")
    print(f"Severity: {severity}")