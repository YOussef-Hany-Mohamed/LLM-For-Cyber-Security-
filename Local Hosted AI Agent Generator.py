import streamlit as st
import json
import time
from llama_cpp import Llama
from crewai import Agent, Task, Crew

# Load local Llama model
MODEL_PATH = "C:/Users/youss/Downloads/llama-2-7b.Q4_K_M.gguf"
llm = Llama(model_path=MODEL_PATH)

class AgentGenerator:
    def __init__(self):
        self.llm = llm
    
    def analyze_prompt(self, user_prompt: str):
        system_prompt = """
        You are an AI expert in cybersecurity and AI agent generation.
        Based on the user's request, generate a CrewAI setup with agents, tasks, and tools.
        Format your response in JSON:
        {
            "agents": [...],
            "tasks": [...]
        }
        """
        
        response = self.llm(f"{system_prompt}\nUser query: {user_prompt}", max_tokens=500)
        try:
            return json.loads(response["choices"][0]["text"])
        except Exception:
            return {"agents": [], "tasks": []}

def create_code_block(config):
    code = ""
    for agent in config["agents"]:
        code += f"""
# Agent: {agent['name']}
agent_{agent['name']} = Agent(
    role='{agent['role']}',
    goal='{agent['goal']}',
    backstory='{agent['backstory']}',
    verbose={agent['verbose']},
    allow_delegation={agent['allow_delegation']},
    tools={agent['tools']}
)

"""
    for task in config["tasks"]:
        code += f"""
# Task: {task['name']}
task_{task['name']} = Task(
    description='{task['description']}',
    agent=agent_{task['agent']},
    expected_output='{task['expected_output']}'
)

"""
    code += """
# Crew Configuration
crew = Crew(
    agents=[" + ", ".join(f"agent_{a['name']}" for a in config["agents"]) + "],
    tasks=[" + ", ".join(f"task_{t['name']}" for t in config["tasks"]) + "]
)
"""
    return code

def main():
    st.set_page_config(page_title="CrewAI Generator", page_icon="🤖", layout="wide")
    st.title("🤖 CrewAI Agent Generator")
    user_prompt = st.text_area("Describe your CrewAI use case:", height=100)
    if st.button("🚀 Generate Crew"):
        with st.spinner("Generating CrewAI setup..."):
            generator = AgentGenerator()
            config = generator.analyze_prompt(user_prompt)
            st.session_state.code = create_code_block(config)
            time.sleep(0.5)
            st.success("✨ Crew generated successfully!")
    if 'code' in st.session_state:
        st.subheader("Generated CrewAI Code")
        st.code(st.session_state.code, language="python")

if __name__ == "__main__":
    main()
