import os
import base64
import io
from pathlib import Path
from typing import Optional, Dict, Any
from PIL import Image
import streamlit as st
import streamlit.components.v1 as components

_component_dir = Path(__file__).parent.absolute()
_nav_paste_bar = components.declare_component(
    "nav_paste_bar",
    path=str(_component_dir)
)

def render_nav_paste_bar(
    placeholder: str = "Ask anything or paste image here (Ctrl+V)...",
    key: Optional[str] = "nav_paste_bar"
) -> Optional[Dict[str, Any]]:
    """
    Renders an enterprise navigation/search bar with a blinking writing cursor
    that supports direct Ctrl+V pasting of clipboard images, screenshots, URLs, or file paths.
    """
    return _nav_paste_bar(placeholder=placeholder, key=key)
