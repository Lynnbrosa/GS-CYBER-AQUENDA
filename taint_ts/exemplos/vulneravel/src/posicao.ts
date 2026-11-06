export async function pedirPosicao() {
  return { lat: -23.543129, lon: -46.643012 };
}

// V8: posição crua (sem arredondar) para a API
export async function v8() {
  const p = await pedirPosicao();
  await fetch(`https://api.exemplo.com/perto?lat=${p.lat}&lon=${p.lon}`);
}

// OK4: posição arredondada, como o app faz
export async function ok4() {
  const p = await pedirPosicao();
  await fetch(`https://api.exemplo.com/perto?lat=${p.lat.toFixed(4)}&lon=${p.lon.toFixed(4)}`);
}

// V9: campo sensível de um objeto que também tem campo público
export async function v9() {
  const p = await pedirPosicao();
  const filtro = { texto: "ubs", lat: p.lat };
  await fetch(`https://api.exemplo.com/busca?q=${filtro.texto}&lat=${filtro.lat}`);
}

// OK5: só o campo público do mesmo objeto
export async function ok5() {
  const p = await pedirPosicao();
  const filtro = { texto: "ubs", lat: p.lat };
  await fetch(`https://api.exemplo.com/busca?q=${filtro.texto}`);
}
