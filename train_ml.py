
from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
ARTIFACTS_DIR = BASE_DIR / "artifacts"

# label 1 = potentially risky pattern
# label 0 = no known risky pattern in this example
SAMPLES = [
    # Potentially risky examples
    ('query = f"SELECT * FROM users WHERE name = {name}"', 1),
    ("result = eval(user_input)", 1),
    ("exec(code_from_user)", 1),
    ("os.system(user_command)", 1),
    ("subprocess.run(command, shell=True)", 1),
    ('password = "my-secret-password"', 1),
    ('api_key = "abc123secret"', 1),
    ('cursor.execute("SELECT * FROM users WHERE id=" + user_id)', 1),
    ('query = "DELETE FROM accounts WHERE id=" + account_id', 1),
    ("eval(request.args.get('expression'))", 1),
    ("exec(request.form['code'])", 1),
    ("os.popen(user_supplied_command)", 1),
    ('secret = "hardcoded-token-value"', 1),
    ('cursor.execute(f"SELECT * FROM products WHERE id={item_id}")', 1),
    ("subprocess.call(user_input, shell=True)", 1),
    ('password = "admin123"', 1),
    ("os.system(input('Command: '))", 1),
    ('query = "UPDATE users SET role=" + role', 1),
    ("eval(serialized_data)", 1),
    ("subprocess.Popen(command, shell=True)", 1),

    # Safer-pattern examples
    ("total = price * quantity", 0),
    ("message = 'Welcome to the application'", 0),
    ("def add(a, b): return a + b", 0),
    ("print('Hello world')", 0),
    ("for item in items: print(item)", 0),
    ("username = input('Username: ')", 0),
    ("count = len(records)", 0),
    ("result = max(scores)", 0),
    ("with open('notes.txt', 'r') as file: text = file.read()", 0),
    ("query = 'SELECT * FROM users WHERE id = ?'", 0),
    ("cursor.execute(query, (user_id,))", 0),
    ("subprocess.run(['git', 'status'], shell=False)", 0),
    ("def multiply(x, y): return x * y", 0),
    ("items = sorted(items)", 0),
    ("safe_name = str(username)", 0),
    ("average = sum(scores) / len(scores)", 0),
    ("for number in numbers: total += number", 0),
    ("message = f'Hello, {username}'", 0),
    ("with open('report.txt', 'w') as file: file.write('Done')", 0),
    ("status = response.status_code", 0),
]


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(SAMPLES, columns=["code", "label"])
    dataset_path = DATA_DIR / "ml_code_samples.csv"
    df.to_csv(dataset_path, index=False)

    X_train, X_test, y_train, y_test = train_test_split(
        df["code"],
        df["label"],
        test_size=0.25,
        random_state=42,
        stratify=df["label"],
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(2, 5),
                min_df=1,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                random_state=42,
            ),
        ),
    ])

    print("Training CodeShield AI ML classifier...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\nTraining examples: {len(X_train)}")
    print(f"Test examples: {len(X_test)}")
    print(f"Test accuracy: {accuracy * 100:.2f}%")

    print("\nClassification report:")
    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["No known risky pattern", "Potentially risky"],
        zero_division=0,
    )
    print(report)

    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    print("Confusion matrix (rows=actual, columns=predicted):")
    print(matrix)

    model_path = ARTIFACTS_DIR / "code_risk_model.joblib"
    joblib.dump(model, model_path)

    metrics = {
        "accuracy": float(accuracy),
        "training_examples": int(len(X_train)),
        "test_examples": int(len(X_test)),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["No known risky pattern", "Potentially risky"],
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": matrix.tolist(),
        "labels": ["No known risky pattern", "Potentially risky"],
        "dataset_note": (
            "Small illustrative dataset. Metrics do not represent "
            "real-world vulnerability detection performance."
        ),
    }

    metrics_path = ARTIFACTS_DIR / "ml_evaluation.json"
    metrics_path.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print(f"\nDataset saved: {dataset_path}")
    print(f"Model saved: {model_path}")
    print(f"Metrics saved: {metrics_path}")
    print("\nML training completed.")


if __name__ == "__main__":
    main()
