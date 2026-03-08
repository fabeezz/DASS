if [ -d "venv" ]; then
    source venv/bin/activate
    echo "✅ Mediul virtual a fost activat."
else
    echo "❌ Eroare: Nu găsesc folderul 'venv'. Te rog să creezi mediul virtual mai întâi!"
    exit 1
fi

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "⚠️ Atenție: Nu am găsit fișierul 'requirements.txt'. Sărim peste instalare."
fi

echo "🔥 Pornim Uvicorn pe portul 8000..."
uvicorn app.main:app --reload