import os, json, copy
import customtkinter as ctk
from utils.paths import DATA_DIR, THEME_WARM_YELLOW

WARM_YELLOW_THEME_JSON = r'''{
  "CTk": {"fg_color": ["#1a1a1a", "#1a1a1a"]},
  "CTkButton": {"fg_color": ["#E67E22", "#D35400"], "hover_color": ["#F39C12", "#E67E22"], "border_color": ["#E67E22", "#D35400"], "text_color": ["#FFFFFF", "#FFFFFF"], "text_color_disabled": ["#7F7F7F", "#7F7F7F"]},
  "CTkLabel": {"text_color": ["#FFFFFF", "#FFFFFF"], "fg_color": "transparent"},
  "CTkEntry": {"fg_color": ["#3A3A3A", "#3A3A3A"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "placeholder_text_color": ["#7F7F7F", "#7F7F7F"]},
  "CTkCheckBox": {"fg_color": ["#E67E22", "#D35400"], "border_color": ["#8A8A8A", "#8A8A8A"], "hover_color": ["#F39C12", "#E67E22"], "text_color": ["#FFFFFF", "#FFFFFF"], "checkmark_color": ["#FFFFFF", "#FFFFFF"]},
  "CTkComboBox": {"fg_color": ["#3A3A3A", "#3A3A3A"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "button_color": ["#E67E22", "#D35400"], "button_hover_color": ["#F39C12", "#E67E22"], "dropdown_fg_color": ["#2E2E2E", "#2E2E2E"], "dropdown_hover_color": ["#3A3A3A", "#3A3A3A"], "dropdown_text_color": ["#FFFFFF", "#FFFFFF"]},
  "CTkFrame": {"fg_color": ["#2E2E2E", "#2E2E2E"], "border_color": ["#5E5E5E", "#5E5E5E"], "top_fg_color": ["#2E2E2E", "#2E2E2E"], "border_width": 0},
  "CTkProgressBar": {"fg_color": ["#5D4037", "#5D4037"], "progress_color": ["#E67E22", "#D35400"], "border_color": ["#5E5E5E", "#5E5E5E"]},
  "CTkScrollableFrame": {"fg_color": ["#1e1e1e", "#1e1e1e"], "border_color": ["#5E5E5E", "#5E5E5E"], "label_fg_color": ["#2E2E2E", "#2E2E2E"], "label_text_color": ["#FFFFFF", "#FFFFFF"]},
  "CTkScrollbar": {"fg_color": ["#2E2E2E", "#2E2E2E"], "button_color": ["#5E5E5E", "#5E5E5E"], "button_hover_color": ["#7A7A7A", "#7A7A7A"]},
  "CTkTextbox": {"fg_color": ["#1a1a1a", "#1a1a1a"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "scrollbar_button_color": ["#5E5E5E", "#5E5E5E"], "scrollbar_button_hover_color": ["#7A7A7A", "#7A7A7A"]},
  "CTkOptionMenu": {"fg_color": ["#3A3A3A", "#3A3A3A"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "button_color": ["#E67E22", "#D35400"], "button_hover_color": ["#F39C12", "#E67E22"]},
  "CTkSlider": {"fg_color": ["#5E5E5E", "#5E5E5E"], "progress_color": ["#E67E22", "#D35400"], "button_color": ["#E67E22", "#D35400"], "button_hover_color": ["#F39C12", "#E67E22"]},
  "CTkSwitch": {"fg_color": ["#5E5E5E", "#5E5E5E"], "progress_color": ["#E67E22", "#D35400"], "button_color": ["#FFFFFF", "#FFFFFF"], "button_hover_color": ["#F39C12", "#E67E22"]},
  "CTkTabview": {"fg_color": ["#2E2E2E", "#2E2E2E"], "border_color": ["#5E5E5E", "#5E5E5E"], "text_color": ["#FFFFFF", "#FFFFFF"], "segmented_button_fg_color": ["#3A3A3A", "#3A3A3A"], "segmented_button_selected_color": ["#E67E22", "#D35400"], "segmented_button_unselected_color": ["#3A3A3A", "#3A3A3A"], "segmented_button_hover_color": ["#F39C12", "#E67E22"]}
}'''

with open(THEME_WARM_YELLOW, 'w', encoding='utf-8') as f:
    f.write(WARM_YELLOW_THEME_JSON)

    THEME_PRESETS = {
    'default': ("dark", "blue"),
    '绿色 (暗绿)': ("dark", "green"),
    '深色暖黄': ("dark", THEME_WARM_YELLOW),
    '浅色蓝': ("light", "blue"),
    '浅色绿': ("light", "green"),
}

def apply_startup_theme(theme_name):
    if theme_name in THEME_PRESETS: mode, color_theme = THEME_PRESETS[theme_name]
    else: mode, color_theme = "dark", "blue"
    try:
        ctk.set_appearance_mode(mode)
        if isinstance(color_theme, str) and os.path.exists(color_theme):
            ctk.set_default_color_theme("blue")
            with open(color_theme, 'r', encoding='utf-8') as f:
                custom_theme = json.load(f)
            merged_theme = copy.deepcopy(ctk.ThemeManager.theme)
            for key, value in custom_theme.items():
                if key in merged_theme: merged_theme[key].update(value)
                else: merged_theme[key] = value
            ctk.ThemeManager.theme = merged_theme
        else:
            ctk.set_default_color_theme(color_theme)
    except Exception as e:
        print(f"主题加载失败: {e}，回退到默认暗蓝")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
