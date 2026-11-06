// Exemplo com vazamentos plantados para provar as regras de rules/aquenda-csharp.yaml.
// Não compila sozinho e não faz parte da API: é só o alvo do Semgrep.
using Microsoft.Extensions.Logging;

public class ChatVazando
{
    private readonly ILogger<ChatVazando> _log;
    private readonly Db _db;

    // V1: texto da mensagem no log
    public void Enviar(string token, int salaId, string texto)
    {
        _log.LogInformation("Mensagem na sala {Sala}: {Texto}", salaId, texto);
    }

    // V2: campo da requisição no log
    public void EnviarDto(NovaMensagemRequisicao req)
    {
        _log.LogWarning("Recusada: " + req.Texto);
    }

    // V3: CEP digitado pela pessoa no log
    public void Geocodificar(string cep)
    {
        var limpo = cep.Replace("-", "");
        _log.LogWarning("CEP {Cep} não encontrado", limpo);
    }

    // V4: token no console
    public void Depurar(string token)
    {
        Console.WriteLine($"token recebido: {token}");
    }

    // V5: token gravado sem hash
    public void Entrar(string token)
    {
        var p = new Participante();
        p.TokenHash = token;
        _db.Add(p);
    }

    // OK1: só o tamanho do texto vai para o log
    public void Medir(string texto)
    {
        _log.LogInformation("Mensagem com {Tamanho} caracteres", texto.Length);
    }

    // OK2: o texto passa pelo mascarador antes
    public void Auditar(string texto)
    {
        _log.LogInformation("Texto: {Texto}", MascaradorPii.Mascarar(texto));
    }

    // OK3: o token vira hash antes de ir para o banco
    public void EntrarCerto(string token)
    {
        var p = new Participante();
        p.TokenHash = ParticipanteChat.HashToken(token);
        _db.Add(p);
    }
}
