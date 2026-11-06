import { useState } from "react";

// V7: o que a pessoa digita no formulário da agenda vai para o servidor
export function Formulario() {
  const [anotacao, setAnotacao] = useState("");
  const salvar = async () => {
    const payload = { anotacao, quando: Date.now() };
    await fetch("https://api.exemplo.com/salvar", { method: "POST", body: JSON.stringify(payload) });
  };
  return { setAnotacao, salvar };
}
