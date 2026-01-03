from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from veritree_gake.core import VeriTreeSimulator

app = FastAPI(title="VeriTree-GAKE Demo")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Single instance of core (stateless per-run)
core = VeriTreeSimulator()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve main demo page"""
    return templates.TemplateResponse("index.html", {"request": request})


import io
from contextlib import redirect_stdout

@app.post("/run", response_class=JSONResponse)
async def run_demo(request: Request):
    data = await request.json()
    try:
        admin = data.get("admin_name", "admin")
        n_mod = int(data.get("n_moderators", 2))
        members_per = int(data.get("members_per_mod", 2))
        kem_algs = data.get("kem_algs", [])
        
        # CAPTURE ALL PRINTS
        output = io.StringIO()
        with redirect_stdout(output):
            result = core.run_demo_tree(admin, n_mod, members_per, kem_algs)
        
        logs = output.getvalue()
        
        return JSONResponse({
            "result": result,
            "logs": logs  # All your prints here!
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)



@app.get("/health", response_class=PlainTextResponse)
async def health():
    """Health check endpoint"""
    return "ok"


if __name__ == '__main__':
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
