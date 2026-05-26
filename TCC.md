---

# Evolução do GASH para suporte a EF e PB

## 1. Visão Geral da Evolução

A versão inicial do GASH foi concebida como uma ferramenta de detecção de smells em workflows do GitHub Actions. Nessa configuração original, o sistema estava fortemente orientado à identificação de padrões problemáticos clássicos, como duplicação, configurações frágeis, uso inseguro de permissões e scripts excessivamente longos. Embora essa abordagem fosse útil para evidenciar problemas recorrentes, ela ainda não refletia integralmente a taxonomia acadêmica de reestruturação de pipelines adotada neste trabalho.

Com base nos dois artigos que orientam esta pesquisa, a ferramenta foi evoluída para contemplar duas dimensões complementares de análise. A primeira dimensão corresponde aos achados **Extra-Functional (EF)**, isto é, problemas e oportunidades de melhoria que afetam propriedades como manutenibilidade, segurança, desempenho e clareza operacional, sem alterar significativamente a política de execução da pipeline. A segunda dimensão corresponde aos achados **Pipeline-Behavior (PB)**, isto é, recomendações associadas à reorganização do comportamento da pipeline, incluindo política de build, estratégia de deploy, estrutura de execução, temporização e observabilidade.

A principal mudança conceitual introduzida foi a transição de uma ferramenta puramente orientada a smells para uma ferramenta de análise estruturada da qualidade de pipelines. Com isso, o GASH passou a emitir findings classificados explicitamente por categoria, subcategoria e severidade, além de suportar uma camada recomendatória voltada a comportamento de pipeline. Essa mudança aproximou a ferramenta da taxonomia acadêmica e ampliou sua utilidade tanto para uso prático quanto para análise empírica em contexto de pesquisa.

---

## 2. Arquitetura

A arquitetura final do GASH foi reorganizada para acomodar, de forma coesa, detectores clássicos de smells e geradores de recomendações de comportamento. O objetivo principal dessa evolução arquitetural foi manter compatibilidade com a estrutura anterior da ferramenta e, ao mesmo tempo, permitir a coexistência explícita entre **EF** e **PB**.

Na versão inicial, a ferramenta era predominantemente detector-first, isto é, o fluxo da análise era estruturado a partir dos detectores individuais, e os resultados eram tratados majoritariamente como mensagens textuais. Essa organização funcionava para uma coleção pequena de análises isoladas, mas não era suficiente para suportar uma taxonomia mais rica, nem para produzir relatórios estruturados ou consumíveis por outros processos.

Na versão final, a arquitetura passou a contar com os seguintes elementos centrais:

1. **parser do workflow**, responsável por transformar o arquivo YAML do GitHub Actions em uma representação interna navegável;
2. **registro central de detectores**, responsável por definir de forma explícita quais detectores compõem a análise;
3. **modelo estruturado de findings**, responsável por representar cada achado de forma uniforme;
4. **camada de normalização e serialização**, responsável por padronizar saída textual e saída em JSON;
5. **camada de recomendações PB**, responsável por inferir oportunidades de melhoria a partir de fatos e métricas extraídos da pipeline.

Essa nova arquitetura permite que detectores EF e PB sejam executados no mesmo pipeline de análise, mas com semânticas distintas. Enquanto os detectores EF permanecem mais próximos de uma abordagem clássica de smell detection, os detectores PB operam como geradores de recomendações baseadas em evidência.

Outra melhoria relevante foi a introdução de um **registro central de detectores**, o que reduziu o acoplamento entre o núcleo da ferramenta e os detectores específicos. Em vez de o sistema depender de uma lista manual espalhada pelo fluxo principal, os detectores agora podem ser organizados e descritos em um ponto central. Isso melhora a manutenção, favorece extensibilidade e torna a arquitetura mais adequada para evolução incremental.

Do ponto de vista de saída, a arquitetura também foi alterada para deixar de priorizar o nome do detector e passar a priorizar o valor analítico do finding. Assim, o relatório final se concentra em categorias, severidades e agrupamentos de interesse, o que é mais aderente ao objetivo de inspeção de qualidade de pipelines.

---

## 3. Modelagem dos Findings

Uma das mudanças mais importantes da evolução do GASH foi a reformulação do modelo de dados usado para representar os resultados da análise. Na versão original, muitos detectores retornavam apenas mensagens textuais ou listas pouco estruturadas. Isso limitava a capacidade de filtrar achados, agrupá-los, exportá-los e relacioná-los com a taxonomia teórica.

Na versão final, cada achado passou a ser representado por uma estrutura explícita contendo, no mínimo:

- **category**
- **subcategory**
- **level**
- **message**

Além desses atributos, a implementação passou a suportar também:

- **detector**, que identifica qual componente gerou o finding;
- **kind**, que indica a natureza do finding, como `SMELL` ou `RECOMMENDATION`;
- **finding_type**, usado em casos específicos, como distinção entre segredo hardcoded e valor genérico hardcoded;
- **metadata**, usado para armazenar evidências, fatos e métricas associadas à recomendação.

Essa modelagem foi adotada para resolver um problema conceitual da versão anterior: a confusão entre **SMELL**, **EF** e **PB**. À luz da taxonomia dos artigos, não fazia sentido manter `SMELL` como categoria principal competindo com `EF` e `PB`. A solução adotada foi tratar **EF** e **PB** como os eixos taxonômicos centrais, enquanto `SMELL` passou a representar apenas a natureza do achado.

Essa decisão foi importante por três razões.

Primeiro, ela torna a modelagem mais fiel à literatura, pois separa claramente o tipo taxonômico da natureza do finding. Segundo, ela permite que a ferramenta represente tanto smells clássicos quanto recomendações contextuais sem forçar todos os resultados a caberem no mesmo molde semântico. Terceiro, ela prepara o sistema para usos mais avançados, como exportação estruturada, filtragem por categoria, sumarização por severidade e construção de datasets de análise.

A padronização do formato textual também foi um ponto central. Todos os findings passaram a ser emitidos com o prefixo:

`[CATEGORY | SUBCATEGORY | LEVEL]`

Por exemplo:

`[EF | SECURITY | CRITICAL] ...`  
`[PB | BUILD_POLICY | LOW] ...`

Esse formato foi escolhido por ser simples, legível e diretamente compatível com a taxonomia de análise proposta neste trabalho.

---

## 4. Estratégia de Classificação Taxonômica

A classificação final do GASH foi estruturada em dois grandes grupos: **EF** e **PB**.

### 4.1. Extra-Functional (EF)

Os achados EF representam problemas e oportunidades de melhoria que afetam qualidades importantes da pipeline, mas que não alteram diretamente sua política de execução. Na implementação final, os findings EF foram organizados nas subcategorias:

- **SECURITY**
- **MAINTAINABILITY**
- **PERFORMANCE**

Essa organização reflete o entendimento de que pipelines podem apresentar fragilidades não apenas de segurança, mas também de manutenção e eficiência.

### 4.2. Pipeline-Behavior (PB)

Os achados PB representam recomendações ligadas à forma como a pipeline se comporta. Isso inclui, por exemplo, política de falha, definição de gating de deploy, uso de builds noturnos, parametrização, timeout, retry e reestruturação das fases de execução.

Na implementação final, os findings PB foram organizados nas subcategorias:

- **INFRASTRUCTURE**
- **BUILD_POLICY**
- **DASHBOARD_NOTIFICATIONS**
- **BUILD_PROCESS_ORGANIZATION**

Essa organização segue a taxonomia apresentada no artigo de reestruturação de pipelines e foi essencial para evitar que problemas de natureza comportamental fossem tratados apenas como “smells genéricos”.

---

## 5. Heurísticas EF

Os detectores EF mantiveram a lógica geral de smell detection, mas foram integrados ao novo modelo taxonômico e estruturado. A seguir, descrevem-se as principais heurísticas por subcategoria.

### 5.1. EF – Maintainability

#### Code Replica

O detector de duplicação busca identificar valores repetidos em variáveis de ambiente, parâmetros de steps e estruturas de jobs. Além disso, ele verifica se dois ou mais jobs possuem assinaturas estruturais equivalentes, isto é, sequências de steps praticamente idênticas. A motivação dessa heurística é que duplicação excessiva aumenta esforço de manutenção, favorece inconsistências futuras e reduz oportunidades de reutilização por reusable workflows ou actions compostas.

#### Extract Environment Variables

Esse detector procura literais repetidos entre diferentes jobs e steps, especialmente URLs, versões, paths e parâmetros com potencial de centralização. A heurística ignora expressões dinâmicas, referências a secrets e casos triviais. Quando um valor é reutilizado em múltiplos contextos, a ferramenta recomenda extraí-lo para `workflow.env` ou variáveis compartilhadas. O racional é que centralização reduz repetição, facilita manutenção e simplifica alterações futuras.

#### Matrix Simplification

A heurística de simplificação de matriz avalia o tamanho expandido da matriz, o número de eixos e o volume de ajustes realizados por `include` e `exclude`. Matrizes muito grandes ou com múltiplas exceções tendem a se tornar difíceis de entender e manter. O finding EF, nesse caso, sugere simplificação estrutural, sem necessariamente alterar a política de cobertura do pipeline.

#### Misconfiguration

O detector de misconfiguration cobre um conjunto amplo de problemas estruturais, incluindo ausência de parâmetros importantes, uso de versões vagas em `uses`, condições `if` excessivamente complexas e configuração inconsistente de `concurrency`. A escolha por agrupar esses problemas em um detector específico decorre do fato de que a robustez de uma pipeline depende não apenas das tarefas que ela executa, mas também da clareza e corretude de sua configuração.

#### Shell Scripts

Esse detector busca steps com scripts inline longos ou complexos demais. A ideia é que blocos shell muito grandes dentro do YAML tornam a workflow mais difícil de ler, revisar, testar e reutilizar. A recomendação, nesses casos, é extrair a lógica para scripts dedicados.

#### Long Block

O detector de blocos longos atua em três níveis: workflow, job e step. Ele procura workflows com muitos jobs, jobs com muitos steps e steps com muitos comandos. A hipótese é que estruturas demasiadamente extensas aumentam o custo cognitivo e dificultam a compreensão global da pipeline.

### 5.2. EF – Performance

#### Cache

A heurística de cache procura comandos de instalação de dependências e verifica se há, anteriormente no job, uma etapa compatível de cache ou setup com cache habilitado. Quando a instalação é feita sem reaproveitamento de dependências, o detector sugere adoção de cache para reduzir custo e tempo de execução. Esse achado foi mantido em EF porque se trata de uma otimização de execução, e não de uma mudança na política de build.

#### Parallel Jobs

Esse detector avalia relações `needs` entre jobs. Quando um job depende de outro sem compartilhar artifacts, outputs ou referências efetivas ao resultado anterior, a dependência pode ser apenas serialização desnecessária. Nesses casos, a ferramenta sugere remoção da dependência para permitir paralelismo. A heurística evita falsos positivos ao desconsiderar relações com semântica evidente de promoção, release ou deploy.

### 5.3. EF – Security

#### Admin By Default

Essa heurística verifica permissões excessivas em nível de workflow e job, especialmente `write` e `write-all`. A motivação é o princípio do menor privilégio. Workflows com permissões excessivas aumentam superfície de risco, especialmente em pipelines com triggers remotos ou dependências externas.

#### Hard-Coded Values and Secrets

Esse detector analisa variáveis de ambiente, parâmetros e comandos shell em busca de valores hardcoded. A implementação diferencia casos genéricos de hardcoding de casos específicos de segredos embutidos. Quando o finding representa um segredo hardcoded, sua severidade é elevada para `CRITICAL`, dada a gravidade direta do problema. Essa distinção foi importante para compatibilizar manutenção e segurança dentro do mesmo detector.

#### Remote Triggers

Esse detector analisa `workflow_dispatch`, `workflow_call` e `workflow_run`, buscando configurações frágeis, inseguras ou excessivamente permissivas. São observados aspectos como permissões elevadas, excesso de inputs, ausência de descrições e uso inadequado de segredos. A motivação é que triggers remotos mal configurados ampliam o impacto potencial de mau uso ou erro operacional.

#### Sudo Usage

A heurística de uso de `sudo` verifica comandos privilegiados em runners Ubuntu hospedados pelo GitHub. Ela diferencia operações sistêmicas legítimas de operações de usuário ou workspace que poderiam ser executadas sem elevação de privilégio. A recomendação visa reduzir risco e aumentar previsibilidade.

#### Unsecure Protocol

Esse detector procura referências a `http://` em valores de ambiente e comandos shell. A presença de protocolos inseguros é tratada como um problema relevante de segurança, pois pode expor tráfego e dados sensíveis.

#### Untrusted Dependencies

Essa heurística consulta metadados de ações externas referenciadas via `uses`, verificando sinais de verificação do mantenedor e possíveis vulnerabilidades conhecidas. Trata-se de um aspecto particularmente importante em pipelines modernas, nas quais a cadeia de supply chain de actions terceiras pode introduzir riscos.

---

## 6. Heurísticas PB

A camada PB foi a principal ampliação conceitual do GASH. Diferentemente dos detectores EF, que continuam próximos da ideia de smell detection, os detectores PB foram projetados como **geradores de recomendações baseadas em fatos**.

Isso significa que um achado PB não é disparado simplesmente pela ausência de uma prática. Em vez disso, ele depende da combinação entre estrutura observada, sinais textuais, propriedades da workflow e métricas derivadas. Essa decisão foi tomada para reduzir falsos positivos, especialmente em ações fortemente dependentes de contexto organizacional.

### 6.1. Extração de fatos e métricas da workflow

Antes de emitir qualquer recomendação PB, a ferramenta constrói uma visão factual da pipeline. Essa visão inclui, entre outros elementos:

- eventos de trigger;
- presença de `schedule`;
- presença de `workflow_dispatch` e inputs;
- tamanho da matriz;
- número de exclusões;
- jobs com `continue-on-error`;
- uso de cache;
- uso estruturado de Docker;
- número de shell steps;
- padrões de retry;
- padrões de waiting;
- canais de notificação;
- steps com bootstrap manual de serviço;
- setup duplicado entre jobs;
- fases inferidas, como install, validation, build, package e deploy.

Esse processo é essencial para que PB seja orientado por evidência e não por simples matching sintático.

### 6.2. PB – Infrastructure

#### A18 – Introduce Dockerization/Containerization

Essa recomendação só é emitida quando há indícios concretos de que a pipeline sofre com fragilidade ambiental, bootstrap repetitivo ou orquestração manual excessiva. Entre os sinais utilizados estão múltiplos comandos Docker manuais em shell, repetição de setup em vários jobs e inicialização manual de serviços. A ausência de Docker, isoladamente, não gera finding. Isso foi uma decisão deliberada para evitar falsos positivos em pipelines simples.

### 6.3. PB – Build Policy

#### A19 – Change How the Build Outcome Is Determined

Essa heurística detecta políticas frágeis de sucesso e falha, como uso de `continue-on-error` em contextos de validação, build ou deploy, além de supressão de falhas via `|| true`, `set +e` e padrões equivalentes. O racional é que a forma como a pipeline determina sucesso ou falha é parte da política de build e, portanto, pertence ao domínio PB.

#### A20 – Skip Useless Tasks/Steps/Environments

A recomendação é gerada quando a workflow executa sempre trabalho aparentemente pesado ou secundário sem filtros de contexto, como steps de documentação, empacotamento ou manutenção rodando em todo push/pull request sem `if`, `paths` ou guardas equivalentes. Também podem ser consideradas matrizes grandes executadas sem qualquer filtro. O achado é formulado como oportunidade, não como erro.

#### A21 – Change Build Matrix Introducing Allow Failure

Essa heurística busca matrizes com rótulos que sugerem versões experimentais, instáveis ou opcionais, como `nightly`, `beta`, `rc` ou `experimental`. Se todas essas combinações forem bloqueantes, a ferramenta recomenda considerar política explícita de não bloqueio. O nível padrão é baixo porque a decisão depende do papel dessas combinações no processo de validação.

#### A22 – Change Dependencies Installation Policy

Aqui a análise não se limita à existência ou não de cache. O foco está na política de instalação: múltiplas estratégias inconsistentes para o mesmo ecossistema, reinstalações redundantes em vários jobs ou mistura de vários ecossistemas dentro de um único bloco shell. O objetivo é identificar oportunidades de padronização da preparação do ambiente.

#### A23 – Introduce/Remove Nightly Builds

Essa recomendação é usada em dois cenários: quando validações relevantes parecem acontecer apenas por agendamento, ou quando tarefas pesadas e não críticas executam continuamente em pushes e pull requests. O wording foi mantido deliberadamente cauteloso, uma vez que a adequação de nightly build depende fortemente do contexto do projeto.

#### A24 – Deploy Only After Build Success

Essa foi uma das heurísticas mais fortes da camada PB. O detector observa jobs de deploy sem dependências explícitas de validação, fluxos em que deploy depende de jobs irrelevantes em vez de checks reais e casos em que deploy ocorre antes de validação no mesmo job. Quando há evidência suficiente, o achado é elevado para `HIGH` ou `CRITICAL`, pois envolve gating inseguro de promoção para release ou produção.

#### A25 – Move from Manual to Automatic Tasks

Essa recomendação é aplicada a workflows que dependem exclusivamente de `workflow_dispatch`, mas realizam atividades rotineiras de build, validação, empacotamento ou documentação. A ideia não é afirmar que toda tarefa manual está errada, e sim sugerir automação quando o padrão indica rotina repetitiva que poderia ser acionada por evento.

### 6.4. PB – Dashboard and Notifications

#### A26 – Improve Readability of the Build Log

Essa heurística identifica longos blocos shell, excesso de `echo` e ausência de nomes em steps de workflows relativamente grandes. O objetivo é melhorar a navegabilidade dos logs e a observabilidade operacional da pipeline.

#### A27 – Restructure the Notification Mechanism

A ferramenta recomenda revisão do mecanismo de notificação quando identifica notificações implementadas de forma ad hoc via shell, webhooks improvisados ou ausência total de notificação explícita em jobs claramente orientados a deploy ou release. Essa recomendação é conservadora, pois o GitHub já fornece notificações básicas por padrão.

### 6.5. PB – Build Process Organization

#### A28 – Update Checks in the Build Process

Essa heurística procura fluxos com build ou deploy sem validação clara. Casos como deploy sem testes, ou package/build sem lint/test/security checks compatíveis com o propósito da workflow, motivam recomendações de atualização da estratégia de verificação.

#### A29 – Reorganize Build Steps Order of Execution

A recomendação é gerada quando a ordem das fases sugere inconsistência lógica, como deploy antes de validation, package antes de validation ou build antes de install. A hipótese é que a ordem das fases carrega significado operacional e que uma ordenação inadequada compromete clareza e governança do pipeline.

#### A30 – Restructure Install and Script Phases

Esse finding é usado quando um mesmo shell step mistura setup, instalação e execução principal, como testar, empacotar ou fazer deploy. A motivação é melhorar separação de responsabilidades dentro da pipeline.

#### A31 – Restructure Jobs and/or Stages

A recomendação surge quando um job concentra fases demais, ou quando a workflow apresenta cadeia serial de dependências longa e potencialmente desnecessária. O objetivo é sugerir decomposição mais limpa entre jobs, estágios ou gates.

#### A32 – Introduce/Change Timeout/Waiting Time for Tasks

Essa heurística trata timeout como política operacional de execução, e não apenas como ausência de configuração. Ela observa jobs sensíveis, como deploy ou package, que não definem timeout, bem como inconsistências fortes entre valores usados em tarefas semelhantes.

#### A33 – Introduce/Remove Retry for Commands

A recomendação cobre tanto pipelines com retry demais, o que pode mascarar falhas persistentes, quanto pipelines com muitas operações de rede e nenhuma política explícita de retry. A ideia é tratar retry como política de resiliência seletiva para falhas transitórias.

#### A34 – Use Parameterized Builds

Essa heurística busca jobs quase idênticos com pequenas variações e workflows manuais sem inputs em contextos claramente configuráveis. O objetivo é recomendar parametrização via matrix, inputs, variáveis ou reusable workflows, sempre de forma conservadora.

---

## 7. Estratégia de Saída e Relato dos Resultados

A saída da ferramenta foi simplificada e alinhada com a taxonomia. Em vez de relatórios centrados no detector, o sistema passou a produzir um resumo estruturado e depois agrupar findings por criticidade, categoria e subcategoria.

Essa escolha tem duas vantagens. A primeira é prática: usuários tendem a compreender melhor riscos e oportunidades quando o relatório prioriza severidade e domínio do problema. A segunda é metodológica: a organização dos resultados por EF e PB facilita análise empírica, comparações entre workflows e estudos estatísticos posteriores.

Além do formato textual, a ferramenta passou a oferecer saída em JSON. Isso amplia sua utilidade para experimentos, mineração de dados e integração com outros artefatos da pesquisa.

---

## 8. Validação da Implementação

A evolução do GASH foi acompanhada por testes automatizados voltados tanto à estrutura dos findings quanto às novas heurísticas PB. Os testes foram organizados para verificar:

- consistência da classificação taxonômica;
- presença correta de categoria, subcategoria e nível;
- formatação do relatório;
- suporte a filtros e serialização em JSON;
- compatibilidade com o modelo legado;
- comportamento das principais recomendações PB.

Essa estratégia de validação foi importante porque a mudança introduzida não foi apenas funcional, mas também semântica. Não bastava que a ferramenta “rodasse”; era necessário garantir que ela passasse a representar adequadamente a nova taxonomia.

---

## 9. Ameaças à Validade

Como toda abordagem heurística, a evolução proposta para o GASH está sujeita a ameaças à validade.

### 9.1. Falsos positivos

A principal ameaça está associada à interpretação incompleta do contexto do projeto. Um workflow pode parecer redundante, manual ou pouco parametrizado, mas essa configuração pode ser intencional por razões organizacionais, regulatórias ou operacionais. Esse risco é particularmente alto em recomendações PB como A18, A23, A25, A27 e A34. Para mitigar esse problema, a ferramenta foi projetada para usar linguagem recomendatória e severidades mais baixas quando a evidência não é forte.

### 9.2. Falsos negativos

Outra ameaça importante é a incapacidade de capturar nuances que dependem de convenções externas ao YAML. Por exemplo, uma pipeline pode delegar lógica a ações compostas, reusable workflows ou scripts externos, o que pode ocultar parte do comportamento real da execução. Nesses casos, a ferramenta pode deixar de identificar problemas ou oportunidades existentes.

### 9.3. Dependência de heurísticas textuais

Parte da análise depende de marcadores textuais, nomes de jobs, nomes de steps e padrões frequentes de comandos. Embora essa técnica seja eficaz na prática, ela não é semanticamente perfeita. Projetos com nomenclaturas muito específicas ou convenções incomuns podem reduzir a precisão das heurísticas.

### 9.4. Generalização limitada

As heurísticas foram desenhadas para GitHub Actions e refletem tanto a estrutura sintática dessa plataforma quanto os padrões descritos nos artigos-base. Portanto, a generalização para outros sistemas de CI/CD exige adaptação. Mesmo dentro de GitHub Actions, projetos de nicho, pipelines altamente especializadas ou ambientes corporativos com políticas próprias podem demandar ajustes adicionais.

### 9.5. Severidade contextual

A severidade atribuída a cada finding segue regras consistentes, mas ainda assim representa uma aproximação. O impacto real de um achado depende do tipo de projeto, do domínio de aplicação, do estágio de maturidade da pipeline e da criticidade operacional do sistema analisado. Assim, os níveis de severidade devem ser interpretados como apoio à priorização, e não como verdade absoluta.

---

## 10. Considerações Finais da Evolução

A evolução do GASH demonstrou que a transição de uma ferramenta centrada apenas em smells para uma ferramenta orientada por taxonomia EF/PB exige mudanças em três níveis: conceitual, arquitetural e heurístico. No nível conceitual, foi necessário redefinir o papel de `SMELL` e promover `EF` e `PB` a categorias principais. No nível arquitetural, foi necessário introduzir um modelo estruturado de findings, um registro central de detectores e um mecanismo de relatório mais coerente com os objetivos da análise. No nível heurístico, foi necessário manter os detectores clássicos de smells e, ao mesmo tempo, criar uma nova camada recomendatória baseada em fatos de pipeline.

Como resultado, o GASH passou a refletir de forma mais fiel a literatura de reestruturação de pipelines e tornou-se mais apropriado tanto para uso prático quanto para investigação científica. Em vez de apenas apontar “cheiros” no workflow, a ferramenta agora é capaz de distinguir problemas extra-funcionais de oportunidades de reorganização comportamental, fornecendo uma visão mais rica e mais alinhada à realidade da engenharia de pipelines modernas.

---

