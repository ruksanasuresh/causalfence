# BrailleTouch — Backend-Centric Architecture

This implements Phases 2–4 from the plan: a working dashboard, a tested
Braille engine, and a motor-communication skeleton — all runnable right now
with zero hardware, using mocked OCR/AI.

## What's real vs mocked right now

| Piece | Status |
|---|---|
| Braille engine (char → dots → motors) | **Real** — full a-z UEB Grade 1 table |
| Session state machine (sentence/word/char navigation, play/pause) | **Real** |
| WebSocket sync to dashboard | **Real** |
| Dashboard UI | **Real** |
| Motor communication (backend → ESP32 controller) | **Real protocol**, fails soft if no ESP32 is connected yet |
| OCR | **Mocked** — returns a fixed sample paragraph, see `backend/services/ocr_service.py` |
| AI summarization | **Mocked** — returns a fixed sample summary, see `backend/services/ai_service.py` |
| ESP32-CAM capture → backend upload | **Real protocol**, untested until you flash `esp32/camera/camera.ino` |

## Running it now (no hardware needed)

```bash
cd backend
pip install -r requirements.txt
python main.py
```

This starts the backend on `http://localhost:8000`.

Then just open `frontend/index.html` directly in a browser — it connects to
`ws://localhost:8000/ws` automatically. Click **Capture** to run the mock
OCR→AI pipeline, then **Start** to watch it step through the summary
character by character, updating the Braille cell, motor status list, and
progress — all with real logic, just no physical device attached yet.
Watch the backend's terminal output: it'll print "Could not reach ESP32
controller" each time, which is expected until Phase 4's hardware step.

## Moving to real hardware (Phase 4 continued)

1. Flash `esp32/controller/motor_controller.ino`, wire the 6 motors per
   the earlier wiring guide (through transistors + flyback diodes).
2. Copy the IP it prints on boot into `backend/config.py`'s
   `ESP32_CONTROLLER_IP`.
3. Restart the backend, click **Start** on the dashboard again — the
   ESP32 should now physically vibrate in sync with what the dashboard
   shows.
4. Test the alphabet thoroughly here before moving on — this is the step
   the original plan explicitly calls out as needing real verification.

## Moving to real capture (Phase 5)

1. Flash `esp32/camera/camera.ino` with your WiFi + the backend's IP.
2. Press its physical CAPTURE button — it POSTs the JPEG straight to
   `/api/capture`.
3. Note: the dashboard's own Capture button currently calls the same
   endpoint with an empty body, which is fine for testing the mock (it
   ignores image content anyway) but isn't a real capture trigger — once
   the ESP32-CAM is live, the physical button is the real capture path.

## Swapping in real OCR (Phase 6) and real AI (Phase 7)

Both are isolated on purpose:
- Replace the body of `run_ocr()` in `ocr_service.py` with a real call
  (Google Vision, Gemini Vision, Tesseract — your choice) — keep the
  signature (`bytes -> str`).
- Replace the body of `summarize()` in `ai_service.py` with a real model
  call using the `SYSTEM_PROMPT` already defined there — keep the
  signature (`str -> str`).

Nothing else in the codebase needs to change when you do this — the
session manager and dashboard don't know or care whether the text came
from a mock or a real API.

## Notes on what's deliberately not built yet

- Numbers and punctuation aren't in the Braille table yet (Grade 1
  a-z only, per the spec's examples) — extend `braille_map.py` if you
  need them.
- "Practice mode" from the dashboard controls list isn't wired up — the
  spec lists it under controls but doesn't define its behavior; flag this
  with your project guide/instructor before building it so it matches
  what they expect a practice mode to actually do.
- The dashboard's CORS is wide open (`allow_origins=["*"]`) for local dev
  convenience — fine for a demo, not something to deploy publicly as-is.
