export const getSecurityAdvice = async (userPrompt: string): Promise<string> => {
  try {
    const res = await fetch("/api/gemini/advisor", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ prompt: userPrompt }),
    });

    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }

    const data = await res.json();
    return data.text || "Não foi possível gerar uma resposta no momento.";
  } catch (error) {
    console.error("Erro ao consultar serviço Gemini:", error);
    return "Erro ao conectar com o serviço de IA no servidor. Por favor, tente novamente.";
  }
};