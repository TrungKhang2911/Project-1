# AI System Risk Assessment

FastAPI backend and React/TypeScript dashboard for deterministic AI system risk assessment. The backend validates the knowledge base and requests with Pydantic, caches the KB in process memory, and calculates residual risk using the context and mitigation formulas.

## Backend

From the project root:

```powershell
python -m pip install -r requirements.txt
Set-Location backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The static knowledge base is `backend/app/data/rule_store.json`. Run the backend tests from `backend` with `python -m pytest -q`. API documentation is available at `http://localhost:8000/docs`.

The default `KB_BACKEND=file` reads the static JSON file. To use MongoDB, set `KB_BACKEND=mongodb`, `MONGODB_URI`, and optionally `MONGODB_DATABASE` / `MONGODB_COLLECTION`. The default database and collection are `ai_risk_assessment` and `rule_store`. Store the complete KB document in the collection; for multi-document collections, give it `_id: "rule_store"`. A single-document collection may use another `_id`. The KB is loaded and validated at application startup, then cached for the process lifetime.

Set `CORS_ORIGINS` to a comma-separated list of trusted frontend origins when deploying. The development defaults allow `http://localhost:3000` and `http://localhost:5173`.

## Frontend

Requires Node.js 22.12 or newer:

```powershell
Set-Location frontend
npm ci
npm run dev
```

The frontend defaults to the API at `http://localhost:8000`. Set `VITE_API_BASE_URL` at build time to use another API origin. Run `npm run build` to create the production bundle in `frontend/dist`.

`overall_risk_score` is the maximum residual score across the evaluated risks; `overall_severity` is its matching threshold. The 5×5 risk matrix rows represent likelihood 1–5, and columns represent impact 1–5.
