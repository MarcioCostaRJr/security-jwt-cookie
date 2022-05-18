# Security JWT by Cookie

Projeto com o intuito em demonstrar a montagem e utilização de JWT armazenado e consumido no Cookie
<br/><br/>
Project with the aim of demonstrating the assembly and use of JWT stored and consumed in the Cookie

## Sobre o projeto / About the project

O projeto foi concebido para tomar como base a geração de JWT armazenando e consumindo o mesmo no Cookie da requisição. 
Através dessa proposta, se fez utilizar como base gerenciamento de validação token por tempo junto a informações previamente
cadastradas numa base H2.
<br/><br/>
The project was conceived to be based on the generation of JWT storing and consuming it in the Cookie of the request.
Through this proposal, it was used as a basis the management of token validation by time together with information previously
registered in an H2 database.


### Requisitos para executar o projeto / Requirements to run the project

- JDK 17
- Maven 3+

## Orientações / Guidelines

Faça um fork do projeto, clone o mesmo, abra na sua IDE de preferência e execute na sua máquina local.
<br /><br />
Fork the project, clone it, open it in your IDE of choice and run it on your local machine.

### Executando / Execution

<p>Ao executar a aplicação você poderá acessar em: http://localhost:8080/</p>

Banco de Dados da API: http://localhost:8080/h2-ui/ <br/>
Se faz necessário a inclusão de registros quando for a primeira utilização da aplicação:

`INSERT INTO roles(name) VALUES('ROLE_USER');` <br/>
`INSERT INTO roles(name) VALUES('ROLE_MODERATOR');` <br/>
`INSERT INTO roles(name) VALUES('ROLE_ADMIN');` <br/>

**Atenção** : Não inclua nenhuma lib ou framework  

<br/>
<p>When running the application you can access: http://localhost:8080/ </p>
Database of API: http://localhost:8080/h2-ui/ <br/>
It is necessary to include records when the application is used for the first time:

`INSERT INTO roles(name) VALUES('ROLE_USER');` <br/>
`INSERT INTO roles(name) VALUES('ROLE_MODERATOR');` <br/>
`INSERT INTO roles(name) VALUES('ROLE_ADMIN');` <br/>

**Attention** : Do not include any libs or frameworks

## Alterações no projeto / Project changes

O conceito usado foi **Responsabilidade por Camada**. Desta forma, a implementação será baseada em sua finalidade técnica. 
Segue:

- **Model** - Pacote de modelagem de negócio
  - **Entity** - Classes de persistência
  - **Enums** - Enumeradores de negócios
  - **DTO** - Objeto de Transferência de Dados
- **Repository** - Comunicação com banco de dados
- **Service** - Serviços para atender às especificações do pacote: spring-security-core
- **Controller** - Interceptadores de requisição HTTP
- **Config** - Componentes de configurações da aplicação

The concept used was **Layer Responsibility**. In this way, the implementation will be based on its technical purpose.
He follows:

- **Model** - Business Modeling Package
  - **Entity** - Persistence classes
  - **Enums** - Business Enumerators
  - **DTO** - Data Transfer Object
- **Repository** - Communication with database
- **Service** - Services to meet package specifications: spring-security-core
- **Controller** - HTTP request interceptors
- **Config** - Application settings components

### Testes integrados / Integrated Tests

Para este projeto, os testes integrados via Postman disponibilizados através de um arquivo que contém requisições, 
conteúdo e outros. Os testes estão disponíveis em uma pasta chamada collections_integrated_tests no projeto.
<br /> <br />
For this project, the integrated tests via Postman made available through a file that contains requests,
content and others. Tests are available in a folder called collections_integrated_tests in the project.