#// Agente.cpp : Defines the entry point for the console application.
//

/* Librerías posiblemente necesarias (pueden no estar todas)*/
//#include "stdafx.h" // IMPORTANTE *** PUEDE DAR FALLOS
#define _CRT_SECURE_NO_WARNINGS // Evita tratar los warnings como errores al compilar 

#include <stdio.h>
#include <conio.h>
#include <string.h>
#include <sys/types.h>
#include <winsock2.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <WS2tcpip.h> //para usar la funcion InetPton que transforma ip string a in_addr
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

// Trazas
#define FICH_TRAZAS "obexgrupo9.log"  // Cambiar <grupo> por el identificador del grupo


// SNMP
#define MAX_MENSAJE_SNMP	2048
#define UDPPORT				161		//Puerto de nuestro ordenador en el que estamos abriendo el socket
#define TRAPPORT			6162	//Puerto de envio de los trap

// Funciones auxiliares
#define LOG(s)	fprintf(flog, "%s", s); fflush(flog);

#define LOGP(s)	fprintf(flog, "%s", s); printf("%s", s); fflush(flog);

#define LOGBYTE(s, len)	{ int i; \
						  fprintf(flog, "\t");          \
						  for (i=0; i<len; i++) \
						  {                      \
							fprintf(flog, "0x%2.2X ", (char) s[i]); \
							if (((i+1)%16 == 0) && (i != 0))                  \
								fprintf(flog, "\n\t");          \
						  }                                 \
						  LOG("\n"); \
						  fflush(flog); \
						}

#define LOGPBYTE(s, len)	{ int i;fprintf(flog, "\t");printf("\t");          \
							  for (i=0; i<len; i++) \
							  {                      \
								fprintf(flog, "0x%2.2X ", (char) s[i]); \
								printf("0x%2.2X ", s[i]); \
								if (((i+1)%16 == 0) && (i != 0))  {                 \
								fprintf(flog, "\n\t");          \
								printf("\n\t"); }                \
							  }                                 \
							  LOGP("\n"); \
							  fflush(flog); \
							}

#define COMPRUEBA_OCTETO(cad, pos, c) \
    { if (cad[pos] != c) \
      { \
        LOGP("Error: Formato incorrecto. Esperado 0x%2.0X   Hallado 0x%2.0X", \
              c, cad[pos]);printf("\n");\
        getchar(); \
        return; \
      } \
      else \
        LOGP("OK: Formato correcto. Esperado 0x%2.0X   Hallado 0x%2.0X", \
              c, cad[pos]);printf("\n");\
    }

/* Posible definición de los tipos de datos básicos */
typedef union
{
	int val_int;   /* para tipo INTEGER */
	char* val_cad; /* para OCTET STRING, OBJECT IDENTIFIER, IpAddress */
} tvalor;

typedef struct valor  /* guardar los valores de las celdas de una tabla */
{
	tvalor val;              /* valor guardado */
	struct valor* sig_fila;  /* apunta al valor de la siguiente fila */
	struct valor* sig_col;   /* apunta al valor de la misma fila en la
							  siguiente columna */
} nvalor;

typedef struct nodo
{
	int tipo_obj;  /* escalar (0), nodo tabla (1), nodo fila (2),
					nodo columna (3) */
	int tipo_de_dato;  /* valores posibles, ej: INTEGER (0),
						OCTET STRING (1), ... */
	int acceso;    /* valores posibles, ej: not-accessible (0),
					read-only (1), read-write (2) */
					/* La cláusula STATUS no se guarda porque sólo se almacenan los
					   nodos 'current'. */
	char oid[2048];     /* para que sea dinámico; se puede comparar como
					una cadena de texto */
	char instancia[2048];
	nvalor tipo_valor;
	int max_bound; /* define el valor máximo para hacer set en caso de que sea un Integer */
	int min_bound; /* define el valor mínimo para hacer set en caso de que sea un Integer */
	struct nodo* sig;  /* apunta al siguiente nodo de la lista */
	struct nodo* indice;  /* apunta al nodo columna índice de esta tabla;
						   sólo tiene sentido si es un nodo fila */
} nodo;

// Variables globales
FILE* flog;


// DEFINICION DE FUNCIONES
void print_hex(const char* buff, unsigned int l);
void read_integer(const char* buff, uint8_t L, nvalor* V);
void read_octetstring(const char* buff, uint8_t L, nvalor* V);
void read_oid(const char* buff, uint8_t L, nvalor* V);
void final_oid(char* oid, const char* cad, uint8_t L);
uint16_t read_tlv(const char* buff, uint8_t* T, uint8_t* L, nvalor* V);
nodo* buscarOID(nodo* MIB, char* oid);
nodo* buscarNextOID(nodo* MIB, char* oid);
size_t oidToBytes(char* oid, uint8_t* bytesoid);
size_t create_response(nodo * MIB, int requestid, uint8_t operation, const char* oid, char* buff, size_t l, uint16_t VBL, uint8_t T, nvalor V, int error, uint16_t* ain, SOCKET s);
nodo* loadMIB();


int main(int argc, char* argv[])
{
	/* Variables para inicialización de sockets */
	WORD wVersionRequested;
	WSADATA wsaData;
	size_t l;
	char buff[MAX_MENSAJE_SNMP];
	sockaddr_in dest;
	sockaddr_in local;

	nodo* MIB;
	uint16_t index = 0, VarBindList = 0; // index apunta a la posicion del buffer en la que vamos a leer y VarBindList al primer par
	uint8_t T, L; // para extraer el tipo y la longitud
	uint8_t operation; // operacion SNMP
	nvalor V; // para extraer el valor
	int rid; // para almacenar el requestID
	char oid[256]; //has the Object Identifier string
	int error = 0; // almacena valores de errores
	uint16_t ain[4]; // array que tiene el número de posicion de los bytes tipo de SNMP Message, SNMP PDU, VarBindList y Varbind
	// para cambiarlos y no tener que crear un paquete nuevo para el get response

	/* Control del número de argumentos de entrada */
	if (argc > 1)  /* 1 ==> Sin argumentos; argv[0] es el nombre del programa */
	{
		printf("No olvide cambiar el numero de argumentos esperado en la plantilla.\n");
		exit(0);
	}

	// Abrir el fichero de trazas (se sobreescribe cada vez)
	flog = fopen(FICH_TRAZAS, "w");
	if (flog == NULL)
	{
		printf("Error al crear el fichero de trazas\n");
		exit(1);
	}

	/* Inicialización de sockets en Windows */
	wVersionRequested = MAKEWORD(2, 2);
	int err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		return -1;
	}
	LOGP("Sockets de Windows inicializados\n");

	// cout << wVersionRequested << " Versionrequested" << endl;

	local.sin_family = AF_INET;
	inet_pton(PF_INET, "127.0.0.1", &local.sin_addr.s_addr);
	local.sin_port = htons(UDPPORT); // choose any

	// creamos la variable del socket y lo creamos
	SOCKET s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
		LOGP("Socket creation error\n");
		return -1;
	}
	// bind to the local address in 127.0.0.1:161
	if (bind(s, (sockaddr*)&local, (socklen_t)sizeof(local)) != 0) {
		LOGP("Bind error\n");
		return -1;
	}

	socklen_t slen;

	//Carga de la MIB
	MIB = loadMIB();

	while (1) {
		index = 0;
		VarBindList = 0;
		error = 0;
		memset(buff, 0, MAX_MENSAJE_SNMP);
		memset(ain, 0, sizeof(ain));
		memset(oid, 0, sizeof(oid));
		fflush(stdout);

		//recibimos la peticion
		slen = sizeof(struct sockaddr_in);
		l = recvfrom(s, buff, MAX_MENSAJE_SNMP, 0, (struct sockaddr*)&dest, &slen);
		cout << "Message received from: " << ntohs(dest.sin_port) << endl;
		if (l == SOCKET_ERROR && l < MAX_MENSAJE_SNMP) {
			LOGP("Error recvfrom\n");
			closesocket(s);
			return -1;
		}
		else if (l > MAX_MENSAJE_SNMP) {
			LOGP("TRAP: Error PORT UNREACHABLE");
			closesocket(s);
			return -1;
		}

		//imprimimos el mensaje en hexadecimal para analizar su composicion
		//recorremos todos los bytes

		cout << "RECEIVED PACKET: " << endl;
		print_hex(buff, l);
		cout << endl;

		//transformamos el mensaje recibido

		//como el mensaje está codificado en ASN.1 lo que tenemos que hacer es ir leyendo todos los TLVs 
		// que se corresponderán con cada uno de los campos del mensaje snmp:
		// Version, communityString, SNMP_PDU(RequestID, Error, ErrorIndex, VarbindList(Varbind(OID, Value)))
		//read_request()

		// version
		index += read_tlv(&buff[index], &T, &L, &V);
		cout << int(T) << " " << int(L) << " " << int(V.val.val_int) << endl;
		if (V.val.val_int != 0) {
			cout << "Este agente solo soporta SNMP version1" << endl;
		}
		else {

			// CommunityString
			index += read_tlv(&buff[index], &T, &L, &V);
			ain[1] = index; // guarda posicion de byte T de SNMP PDU
			cout << int(T) << " " << int(L) << " " << V.val.val_cad << endl;

			if (strcmp(V.val.val_cad, "public") != 0) {
				cout << "Community String is not 'public'" << endl;
			}
			else {

				// SNMP_PDU OPERATION
				index += read_tlv(&buff[index], &T, &L, &V);
				if (T != 160 && T != 161 && T != 163) {
					cout << "Not valid SNMP Operation" << endl;
				}
				else {

					operation = T;

					// RequestID
					index += read_tlv(&buff[index], &T, &L, &V);
					cout << int(T) << " " << int(L) << " " << V.val.val_int << endl;
					rid = V.val.val_int;

					// Error
					index += read_tlv(&buff[index], &T, &L, &V);
					cout << int(T) << " " << int(L) << " " << V.val.val_int << endl;

					// ErrorIndex
					index += read_tlv(&buff[index], &T, &L, &V);
					cout << int(T) << " " << int(L) << " " << V.val.val_int << endl;

					//guarda posiciones del byte T de VarBindList y VarBind
					ain[2] = index;
					ain[3] = index + 2;

					// TEMP *** y si se hace get de varios objetos?

					// ObjectIdentifier
					index += read_tlv(&buff[index], &T, &L, &V);
					cout << int(T) << " " << int(L) << " ";
					cout << "OID ";

					final_oid(oid, V.val.val_cad, L);

					cout << oid << endl << endl;

					VarBindList = index; // Guarda la posicion del primer valor para luego modificarlo más facilmente

					// Value
					index += read_tlv(&buff[index], &T, &L, &V);
					cout << int(T) << " " << int(L) << " ";
					if (T == 5) {
						cout << "NULL";
					}
					else if(T == 2){
						cout << V.val.val_int << endl;
					}
					else {
						cout << V.val.val_cad << endl;
					}

					cout << int(uint8_t(buff[ain[0] + 1])) << " " << int(uint8_t(buff[ain[1] + 1]));

					l = create_response(MIB, rid, operation, oid, buff, l, VarBindList, T, V, error, &ain[0], s);

				}
			}
		}

		//enviamos la respuesta
		cout << "message SENT to: " << ntohs(dest.sin_port) << endl;
		int ret = sendto(s, buff, l, 0, (const struct sockaddr*)&dest, (socklen_t)sizeof(dest));
		cout << "NUM BYTES SENT" << ret << endl;

	}

	/* Cierre */
	if (flog != NULL)
		fclose(flog);
	exit(0);
}


// IMPLEMENTACIÓN DE LAS FUNCIONES

/*
* Imprime todos los bytes separados en 4 bits en decimal, parecido a como se representa un paquete en hexadecimal en
* Wireshark pero sin cambiar 10 por a, 11 por b, 12 por c, etc...
*/
void print_hex(const char* buff, unsigned int l) {

	uint8_t c;

	for (unsigned i = 0; i < l; i++) {
		c = (uint8_t)buff[i];
		cout << unsigned(c >> 4) << unsigned(c & 15) << " ";
		if (unsigned(c >> 4) > 15) {
			cout << endl << endl << endl << int(c) << " " << unsigned(c) << endl << endl << endl;
		}
	}

	cout << endl << endl;
}


/*
* Introduce en valor un entero
*/
// TEMP *** para enteros negativos?
void read_integer(const char* buff, uint8_t L, nvalor* V) {

	int v = 0;
	// TEMP *** ALEX, si tiene mas de 4 octetos esto da problemas porque es un int.
	// aplazamos 8 bits a la izquierda y añadimos los bits a la derecha
	for (int i = 0; unsigned(i) < L; i++) {
		v = v << 8;
		v = v | uint8_t(buff[i]);
	}

	//v tiene el valor del integer
	V->val.val_int = v;
}

/*
* Introduce en valor un octet string
*/
void read_octetstring(const char* buff, uint8_t L, nvalor* V) {

	//creamos memoria para la longitud
	// TEMP *** liberar memoria una vez que hayas usado el valor obtenido
	V->val.val_cad = (char*)malloc(L + 1); // el string y un '\0'
	if (V->val.val_cad == NULL) {
		cout << "ERROR, memory asignation, read_octectstring" << endl;
	}

	memcpy((char*)V->val.val_cad, buff, L);
	V->val.val_cad[L] = '\0';
}

/*
*
*/
void read_oid(const char* buff, uint8_t L, nvalor* V) {
	//creamos memoria para la longitud
	// TEMP *** liberar memoria una vez que hayas usado el valor obtenido
	V->val.val_cad = (char*)malloc(L); // el string y un '\0'
	if (V->val.val_cad == NULL) {
		cout << "ERROR, memory asignation, read_oid" << endl;
	}

	memcpy((char*)V->val.val_cad, buff, L);
	V->val.val_cad[L] = '\0';
}

/*
* Dada la cadena cad con los bytes del oid, introduce en la cadena oid el oid correspondiente
* preparado para sacarlo por pantalla.
*/
void final_oid(char* oid, const char* cad, uint8_t L) {

	char temp[8];

	int x = int(cad[0]) / 40;
	int  y = int(cad[0]) - (x * 40);
	sprintf(oid, "%d.%d.", x, y);

	for (int i = 1; i < L; i++) {

		if (i < (L - 1)) {
			sprintf(temp, "%d.", int(cad[i]));
		}
		else {
			sprintf(temp, "%d", int(cad[i]));
		}

		strcat(&oid[strlen(oid)], temp);
	}
}

/*
* Introduces el buffer y devuelve el offset en el buffer tras haber leido el primer valor
*/
uint16_t read_tlv(const char* buff, uint8_t* T, uint8_t* L, nvalor* V) {

	uint16_t index = 0;

	*T = buff[0];
	*L = buff[1];

	index += 2; // ahora estamos en la posicion del valor

	// dependiendo del tipo que hayamos leido hacemos una cosa u otra

	switch (*T) {

		// INTEGER (0x02)
	case 2:
		// el integer puede tener múltiples octetos así que leemos L bytes y los pasamos a integer
		read_integer(&buff[index], *L, V);
		index += *L;
		break;
		// OCTET STRING (0x04)
	case 4:
		cout << "OCTET STRING" << endl;
		read_octetstring(&buff[index], *L, V);
		index += *L;
		break;

		// NULL (0x05)
	case 5:
		break;

		// OID (0x06)
	case 6:
		cout << "OBJECT IDENTIFIER" << endl;
		read_oid(&buff[index], *L, V);
		index += *L;
		break;

		// SEQUENCE OF (0x30)
	case 48:
		// siempre que sea una secuencia seguimos leyendo TLV hasta que encontremos un valor que no sea construido
		index += read_tlv(&buff[index], T, L, V);
		break;

		// SNMP OPERATIONS
		// GET (0xA0)
	case 160:
		cout << "SNMP GET OPERATION" << endl;
		break;

		// GETNEXT (0xA1)
	case 161:
		cout << "SNMP GETNEXT OPERATION" << endl;
		break;

		// SET (0xA3)
	case 163:
		cout << "SNMP SET OPERATION" << endl;
		break;

	default:
		cout << "ERROR, NOT KNOWN ASN1 TYPE" << endl;
		break;
	}

	return index;
}

nodo * buscarOID(nodo* MIB, char* oid) {
	
	nodo *aux = MIB;

	cout << endl << endl << "BUSCAROID DEBUG:" << endl;
	cout << oid << "\t\t ---> " << aux->instancia << endl;

	while ((aux != NULL) && (strcmp(oid, aux->instancia) != 0)) {
		aux = aux->sig;
		cout << oid << "\t\t ---> " << aux->instancia << endl;
	}

	return aux;

}

nodo* buscarNextOID(nodo* MIB, char* oid) {

	// TEMP *** Estamos cogiendolo con los oid cuando deberíamos de comprobarlo 
	// con las instancias para poder hacer un getnext a una fila específica.

	nodo* aux = MIB;

	cout << endl << endl << "BUSCAROID DEBUG:" << endl;
	cout << oid << "\t\t ---> " << aux->oid << endl;

	while ((aux != NULL) && (strcmp(oid, aux->oid) != 0)) {
		aux = aux->sig;
		cout << oid << "\t\t ---> " << aux->oid << endl;
	}

	aux = aux->sig;
	cout << oid << "\t\t ---> " << aux->oid << endl;
	while ((aux->tipo_obj == 1) || (aux->tipo_obj == 2)) {
		aux = aux->sig;
		cout << oid << "\t\t ---> " << aux->oid << endl;
	}

	return aux;
}

nodo* buscarNextOIDv2(nodo* MIB, char* oid) {

	// TEMP *** Estamos cogiendolo con los oid cuando deberíamos de comprobarlo 
	// con las instancias para poder hacer un getnext a una fila específica.

	nodo* aux = MIB;

	cout << endl << endl << "BUSCAROID DEBUG:" << endl;
	cout << oid << "\t\t ---> " << aux->instancia << endl;

	while ((aux != NULL) && (strcmp(oid, aux->instancia) != 0)) {
		aux = aux->sig;
		cout << oid << "\t\t ---> " << aux->instancia << endl;
	}

	aux = aux->sig;
	while ((aux->tipo_obj == 1) || (aux->tipo_obj == 2)) {
		aux = aux->sig;
		cout << oid << "\t\t ---> " << aux->oid << endl;
	}

	return aux;
}

//dado un oid en cadena, crea el oid en bytes y devuelve el número de bytes que ocupa
// suponemos que todos los números se codifican como 1 byte y que no puede haber numeros
// mas grandes de 1 byte
size_t oidToBytes(char* oid, uint8_t * bytesoid) {

	size_t contador = 0;
	char ptr[256];
	char* p = NULL;
	int temp = 0;

	// copiamos el oid en la variable ptr para no modificar la mib
	strcpy(ptr, oid);

	// gets the first number (token)
	p = strtok(ptr, ".");
	temp = atoi(p)*40;

	// gets the second number
	p = strtok(NULL, ".");
	temp = temp + atoi(p);

	// gets the rest of numbers
	while (p != NULL) {

		if (contador == 0)
			bytesoid[contador] = temp;
		else
			bytesoid[contador] = atoi(p);

		contador++;

		p = strtok(NULL, ".");
	}

	return contador;

}

size_t create_trap(char* msg, nodo* actual, nvalor V) {


	size_t loid;
	uint8_t bytesoid[256];
	memset(bytesoid, 0, sizeof(bytesoid));

	// convertimos el oid a bytes y almacenamos su longitud
	loid = oidToBytes(actual->oid, bytesoid);

	// FORMAMOS EL PAQUETE

	//SNMP MESSAGE
	msg[0] = 48;
	msg[1] = (2+1) + (2+6) + (2) + (2 + loid) + (2 + 4) + (2 + 1) + (2 + 1) + (2 + 2);

	// Version
	msg[2] = 2;
	msg[3] = 1;
	msg[4] = 1; // version SNMPv1

	// Comunidad
	msg[5] = 4;
	msg[6] = 6;
	memcpy(&msg[7], "public", 6);

	// Tipo de PDU -> TRAP
	msg[13] = (uint8_t)164;
	msg[14] = (2 + loid) + (2+4) + (2+1) + (2+1) + (2+2);
	
	// OID del OBJETO
	msg[15] = 6;
	msg[16] = loid;
	memcpy(&msg[17], bytesoid, loid);
	
	// Direccion IP del agente
	msg[17 + loid] = 64;
	msg[18 + loid] = 4;
	msg[19 + loid] = 127;
	msg[20 + loid] = 0;
	msg[21 + loid] = 0;
	msg[22 + loid] = 1;

	// Tipo de notificacion
	msg[23 + loid] = 2;
	msg[24 + loid] = 1;
	msg[25 + loid] = 6;

	// Codigo especifico
	msg[26 + loid] = 2;
	msg[27 + loid] = 1;
	msg[28 + loid] = V.val.val_int;

	// Tiempo del agente
	// TEMP *** en wikipedia pone entero de 32 bits
	msg[29 + loid] = 67;
	msg[30 + loid] = 2;
	msg[31 + loid] = 2;
	msg[32 + loid] = 121;

	return 33 + loid;

}


size_t create_response(nodo * MIB, int requestid, uint8_t operation, const char* oid, char* buff, size_t l, uint16_t VBL, uint8_t T, nvalor V, int error, uint16_t* ain, SOCKET s) {

	int valtype; // tipo del valor del objeto a leer
	uint8_t seterror = 0; //almacena errores
	uint8_t seterror_index = 0; // apunta al valor en el que ha fallado la operacion set.
	uint8_t added = 0; //numero de bytes añadidos al crear el response con respecto al request
	uint8_t bytesoid[256]; // almacena el oid en bytes una vez transformado de cadena
	char* octetstr[256]; // almacena el valor OCTET STRING que lee de la mib
	nodo* auxiliar = NULL;
	size_t oidlong = 0; // almacena la longitud del oid en bytes nuevo al hacer getNext
	char bufftemp[MAX_MENSAJE_SNMP]; // copia del buffer para realizar operaciones sobre el
	char trapmsg[MAX_MENSAJE_SNMP]; // para crear el mensaje trap cuando se hace set fuera de los límites
	size_t ltrap; // almacena la longitud del mensaje trap creado

	// Responses:
	// GetRequest o GetNextrequest, devuelve un GetResponse con el nombre y valor para cada uno de los objetos del VarBindList
	// SetRequest, devuelve un GetResponse igual que el SetRequest, si hay fallo al escribir (Read-only) pone en 
	// error-status el valor noSuchName, badValue o genErr y error-index apunta al elemento que ha provocado el error
	// si la operación set se hace correctamente -> error-status a noError y error-index a cero.

	//vemos que operacion tenemos que hacer
	switch (operation) {

		// GET
	case 160:

		/*
		* Comprueba si el OID no existe o si el acceso es not-accessible
		* Comprueba el tipo de valor a leer y lo mete en valtype 0 -> INTEGER, u OTRO
		* Lee el valor y lo introduce en V.val.val_int o V.val.val_int dependiendo del tipo
		*/
		//comprueba el tipo de valor a leer

		auxiliar = buscarOID(MIB, (char*)oid);


		if (auxiliar == NULL || auxiliar->acceso == 0) { //El OID no existe o no se puede acceder
			seterror = 2; //noSuchName
			seterror_index = 1;
			buff[ain[2] - 4] = seterror;
			buff[ain[2] - 1] = seterror_index;
		}
		else {
			valtype = auxiliar->tipo_de_dato;
			if (valtype == 0) { // tipo integer

				// se cambia el valor NULL por el correspondiente

				buff[VBL] = 2; // indicamos que es de tipo int
				// vemos cuantos bytes necesita ese int
				buff[VBL + 1] = 1; // TEMP *** PABLO aquí ver la cantidad de bytes que se necesitan para el integer y cambiarla por el 1 que hay = 1 por = long;
				added = uint16_t(buff[VBL + 1]);
				V.val.val_int = auxiliar->tipo_valor.val.val_int; //Lee de la MIB con ese OID en el valor nvalor V
				buff[VBL + 2] = uint8_t(V.val.val_int);

				// sumamos los valores añadidos a las longitudes, en ain tenemos la posicion de los Type, así que le sumamos 1
				for (int i = 0; i < 4; i++) {
					buff[ain[i] + 1] = uint8_t(buff[ain[i] + 1]) + added;
				}

				//ponemos el tipo a GetResponse (162)
				buff[ain[1]] = uint8_t(162);
			}
			else { // cualquier otro tipo se trata como cadena

				buff[VBL] = 4; // TEMP *** PABLO Aquí indicar el tipo que es OCTET STRING, IP LO QUE SEA, ETC.
				V.val.val_cad = auxiliar->tipo_valor.val.val_cad;
				buff[VBL + 1] = strlen(V.val.val_cad);
				added = uint16_t(buff[VBL + 1]);
				memcpy(&buff[VBL + 2], V.val.val_cad, added);

				// sumamos los valores añadidos a las longitudes, en ain tenemos la posicion de los Type, así que le sumamos 1
				for (int i = 0; i < 4; i++) {
					buff[ain[i] + 1] = uint8_t(buff[ain[i] + 1]) + added;
				}

			}

			// TEMP *** añadir el tipo ipAddress
		}

		//ponemos el tipo a GetResponse (162)
		buff[ain[1]] = uint8_t(162);

		break;

		// GETNEXT
	case 161:

		// auxiliar = buscarNextOID(MIB, (char*)oid); // TEMP *** 
		auxiliar = buscarNextOIDv2(MIB, (char*)oid);

		if (auxiliar == NULL || auxiliar->acceso == 0) { //El OID no existe o no se puede acceder
			seterror = 2;
			seterror_index = 1;
			buff[ain[2] - 4] = seterror;
			buff[ain[2] - 1] = seterror_index;
		}
		else {
			valtype = auxiliar->tipo_de_dato;
			if (valtype == 0) { // tipo integer

				// se cambia el valor NULL por el correspondiente

				buff[VBL] = 2; // indicamos que es de tipo int
				// vemos cuantos bytes necesita ese int
				buff[VBL + 1] = 1; // TEMP *** PABLO aquí ver la cantidad de bytes que se necesitan para el integer y cambiarla por el 1 que hay = 1 por = long;
				added = uint16_t(buff[VBL + 1]);
				V.val.val_int = auxiliar->tipo_valor.val.val_int;
				buff[VBL + 2] = uint8_t(V.val.val_int);

				//codificamos el valor del oid siguiente al que hemos hecho GetNext
				oidlong = oidToBytes(auxiliar->oid, bytesoid);

				// copiamos el buffer en un buffer temporal
				memcpy(bufftemp, buff, l + added);
				
				// desplazamos el valor la cantidad de bytes añadidos si añadiesemos el nuevo oid
				int loidpos= ain[3]+3;
				memcpy(&buff[loidpos + oidlong], &bufftemp[loidpos+int(bufftemp[loidpos])], l+added-(loidpos+int(bufftemp[loidpos])));
				
				// introducimos el nuevo oid
				memcpy(&buff[loidpos + 1], &bytesoid, oidlong);

				//añadimos la longitud que hemos introducido al meter el nuevo oid, o la que hemos quitado
				added += oidlong - int(buff[loidpos]);

				// sumamos los valores añadidos a las longitudes, en ain tenemos la posicion de los Type, así que le sumamos 1
				for (int i = 0; i < 4; i++) {
					buff[ain[i] + 1] = uint8_t(buff[ain[i] + 1]) + added;
				}

				//ponemos el tipo a GetResponse (162)
				buff[ain[1]] = uint8_t(162);

			}
			else { // cualquier otro tipo se trata como cadena

				buff[VBL] = 4; // TEMP *** PABLO Aquí indicar el tipo que es OCTET STRING, IP LO QUE SEA, ETC.
				V.val.val_cad = auxiliar->tipo_valor.val.val_cad;
				buff[VBL + 1] = strlen(V.val.val_cad);
				added = uint16_t(buff[VBL + 1]);
				memcpy(&buff[VBL + 2], V.val.val_cad, added);

				//codificamos el valor del oid siguiente al que hemos hecho GetNext
				oidlong = oidToBytes(auxiliar->oid, bytesoid);

				// copiamos el buffer en un buffer temporal
				memcpy(bufftemp, buff, l + added);

				// desplazamos el valor la cantidad de bytes añadidos si añadiesemos el nuevo oid
				int loidpos = ain[3] + 3;
				memcpy(&buff[loidpos + oidlong], &bufftemp[loidpos + int(bufftemp[loidpos])], l + added - (loidpos + int(bufftemp[loidpos])));

				// introducimos el nuevo oid
				memcpy(&buff[loidpos + 1], &bytesoid, oidlong);

				//añadimos la longitud que hemos introducido al meter el nuevo oid, o la que hemos quitado
				added += oidlong - int(buff[loidpos]);

				// sumamos los valores añadidos a las longitudes, en ain tenemos la posicion de los Type, así que le sumamos 1
				for (int i = 0; i < 4; i++) {
					buff[ain[i] + 1] = uint8_t(buff[ain[i] + 1]) + added;
				}
			}
		}

		//ponemos el tipo a GetResponse (162)
		buff[ain[1]] = uint8_t(162);
		
		break;

		// SET
	case 163:

		auxiliar = buscarOID(MIB, (char*)oid);


		if (auxiliar == NULL || auxiliar->acceso == 0) { //El OID no existe o no se puede acceder
			seterror = 2;
			seterror_index = 1;
		}
		else if (auxiliar->acceso == 1) { //Read-only
			seterror = 4;
			seterror_index = 1;
		}
		else {
			valtype = auxiliar->tipo_de_dato;
			if (valtype == 0) { // tipo integer
				
				// miramos si está dentro de los bounds
				if (V.val.val_int < auxiliar->min_bound || V.val.val_int > auxiliar->max_bound) {
					cout << endl << "EL INTEGER NO SE CORRESPONDE CON LOS LIMITES" << endl;
					cout << "============================================" << endl << endl;

					seterror = 3; // badValue error
					seterror_index = 1;

					// Formamos el trap
					ltrap = create_trap(trapmsg, auxiliar, V);
					// Enviamos el trap
					cout << endl << "TRAP MSG: " << endl;
					print_hex(trapmsg, ltrap);

					// Enviamos el paquete al puerto TRAPPORT
					sockaddr_in trapdest;
					trapdest.sin_family = AF_INET;
					inet_pton(PF_INET, "127.0.0.1", &trapdest.sin_addr.s_addr);
					trapdest.sin_port = htons(TRAPPORT); // choose any
					int ret = sendto(s, trapmsg, ltrap, 0, (const struct sockaddr*)&trapdest, (socklen_t)sizeof(trapdest));
					cout << "message SENT to: " << ntohs(trapdest.sin_port) << " - " << ret << " bytes" << endl;
				}
				else {
					auxiliar->tipo_valor.val.val_int = V.val.val_int;
				}
			}
			else {
				auxiliar->tipo_valor.val.val_cad = V.val.val_cad;
			}
		}

		// ain[2] está justo en el tipo despues de error index, y suponiendo que error y error index sean integers de 
		// longitud 1 modificamos sus valores de la siguiente forma

		buff[ain[2] - 4] = seterror;
		buff[ain[2] - 1] = seterror_index;
		
		// ponemos el tipo GetResponse en el paquete recibido
		buff[ain[1]] = uint8_t(162);
		
		break;
	}

	return l + added;

}

/*
* Método para cargar la MIB en el agente
*/
nodo* loadMIB() {
	nodo* nombreDispositivo = NULL, * personaContacto = NULL, * personasEntran, * personasSalen, * ipDisp,
		tablaHistoricos, filaTablaHistoricos, diaAno[2], nEntradas[2], nSalidas[2],
		tablaDispositivos, filaTablaDispositivos, ipDispositivo[2], modeloDispositivo[2], tipoTarjeta[2], fechaInstalacion[2],
		tablaRevisiones, filaTablaRevisiones, dia[2], nombrePersona[2];

	nombreDispositivo = (nodo*)malloc(sizeof(nodo));
	personaContacto = (nodo*)malloc(sizeof(nodo));
	personasEntran = (nodo*)malloc(sizeof(nodo));
	personasSalen = (nodo*)malloc(sizeof(nodo));
	ipDisp = (nodo*)malloc(sizeof(nodo));

	nombreDispositivo->tipo_obj = 0;
	nombreDispositivo->tipo_de_dato = 1;
	nombreDispositivo->acceso = 1;
	memset(nombreDispositivo->oid, '\0', MAX_MENSAJE_SNMP);
	memset(nombreDispositivo->instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(nombreDispositivo->oid, "1.3.6.1.3.53.9.1");
	strcpy(nombreDispositivo->instancia, "1.3.6.1.3.53.9.1.0");
	nombreDispositivo->tipo_valor.val.val_cad = (char*)"Gestor de seguridad";
	nombreDispositivo->tipo_valor.sig_fila = NULL;
	nombreDispositivo->tipo_valor.sig_col = NULL;
	nombreDispositivo->sig = personaContacto;
	nombreDispositivo->indice = NULL;

	personaContacto->tipo_obj = 0;
	personaContacto->tipo_de_dato = 1;
	personaContacto->acceso = 1;
	memset(personaContacto->oid, '\0', MAX_MENSAJE_SNMP);
	memset(personaContacto->instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(personaContacto->oid, "1.3.6.1.3.53.9.2");
	strcpy(personaContacto->instancia, "1.3.6.1.3.53.9.2.0");
	personaContacto->tipo_valor.val.val_cad = (char*)"Chema Alonso";
	personaContacto->tipo_valor.sig_fila = NULL;
	personaContacto->tipo_valor.sig_col = NULL;
	personaContacto->sig = personasEntran;
	personaContacto->indice = NULL;


	// TEMP *** Hace falta poner el min_bound y max_bound en el resto de valores que no son 
	// de tipo INTEGER?
	personasEntran->tipo_obj = 0;
	personasEntran->tipo_de_dato = 0;
	personasEntran->acceso = 2;
	memset(personasEntran->oid, '\0', MAX_MENSAJE_SNMP);
	memset(personasEntran->instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(personasEntran->oid, "1.3.6.1.3.53.9.3");
	strcpy(personasEntran->instancia, "1.3.6.1.3.53.9.3.0");
	personasEntran->tipo_valor.val.val_int = 10;
	personasEntran->tipo_valor.sig_fila = NULL;
	personasEntran->tipo_valor.sig_col = NULL;
	personasEntran->min_bound = 3;
	personasEntran->max_bound = 50;
	personasEntran->sig = personasSalen;
	personasEntran->indice = NULL;

	personasSalen->tipo_obj = 0;
	personasSalen->tipo_de_dato = 0;
	personasSalen->acceso = 2;
	memset(personasSalen->oid, '\0', MAX_MENSAJE_SNMP);
	memset(personasSalen->instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(personasSalen->oid, "1.3.6.1.3.53.9.4");
	strcpy(personasSalen->instancia, "1.3.6.1.3.53.9.4.0");
	personasSalen->tipo_valor.val.val_int = 7;
	personasSalen->tipo_valor.sig_fila = NULL;
	personasSalen->tipo_valor.sig_col = NULL;
	personasSalen->min_bound = 10;
	personasSalen->max_bound = 30;
	personasSalen->sig = ipDisp;
	personasSalen->indice = NULL;

	ipDisp->tipo_obj = 0;
	ipDisp->tipo_de_dato = 1;
	ipDisp->acceso = 1;
	memset(ipDisp->oid, '\0', MAX_MENSAJE_SNMP);
	memset(ipDisp->instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(ipDisp->oid, "1.3.6.1.3.53.9.5");
	strcpy(ipDisp->instancia, "1.3.6.1.3.53.9.5.0");
	ipDisp->tipo_valor.val.val_cad = (char*)"192.168.1.2";
	ipDisp->tipo_valor.sig_fila = NULL;
	ipDisp->tipo_valor.sig_col = NULL;
	ipDisp->sig = &tablaHistoricos;
	ipDisp->indice = NULL;

	tablaHistoricos.tipo_obj = 1;
	tablaHistoricos.tipo_de_dato = NULL;
	tablaHistoricos.acceso = 0;
	memset(tablaHistoricos.oid, '\0', MAX_MENSAJE_SNMP);
	memset(tablaHistoricos.instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(tablaHistoricos.oid, "1.3.6.1.3.53.9.6");
	strcpy(tablaHistoricos.instancia, "");
	tablaHistoricos.tipo_valor.val.val_cad = (char*)"";
	tablaHistoricos.tipo_valor.sig_fila = NULL;
	tablaHistoricos.tipo_valor.sig_col = NULL;
	tablaHistoricos.sig = &filaTablaHistoricos;
	tablaHistoricos.indice = NULL;

	filaTablaHistoricos.tipo_obj = 2;
	filaTablaHistoricos.tipo_de_dato = NULL;
	filaTablaHistoricos.acceso = 0;
	memset(filaTablaHistoricos.oid, '\0', MAX_MENSAJE_SNMP);
	memset(filaTablaHistoricos.instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(filaTablaHistoricos.oid, "1.3.6.1.3.53.9.6.1");
	strcpy(filaTablaHistoricos.instancia, "");
	filaTablaHistoricos.tipo_valor.val.val_cad = (char*)"";
	filaTablaHistoricos.tipo_valor.sig_fila = NULL;
	filaTablaHistoricos.tipo_valor.sig_col = NULL;
	filaTablaHistoricos.sig = &diaAno[0];
	filaTablaHistoricos.indice = diaAno;

	diaAno[0].tipo_obj = 4;
	diaAno[0].tipo_de_dato = 1;
	diaAno[0].acceso = 1;
	memset(diaAno[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(diaAno[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(diaAno[0].oid, "1.3.6.1.3.53.9.6.1.1");
	strcpy(diaAno[0].instancia, "1.3.6.1.3.53.9.6.1.1.20-12-20");
	diaAno[0].tipo_valor.val.val_cad = (char*)"20-12-20";
	diaAno[0].tipo_valor.sig_fila = &diaAno[1].tipo_valor;
	diaAno[0].tipo_valor.sig_col = &nEntradas[0].tipo_valor;
	diaAno[0].sig = &diaAno[1];
	diaAno[0].indice = NULL;

	diaAno[1].tipo_obj = 4;
	diaAno[1].tipo_de_dato = 1;
	diaAno[1].acceso = 1;
	memset(diaAno[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(diaAno[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(diaAno[1].oid, "1.3.6.1.3.53.9.6.1.1");
	strcpy(diaAno[1].instancia, "1.3.6.1.3.53.9.6.1.1.21-12-20");
	diaAno[1].tipo_valor.val.val_cad = (char*)"21-12-20";
	diaAno[1].tipo_valor.sig_fila = NULL;
	diaAno[1].tipo_valor.sig_col = &nEntradas[1].tipo_valor;
	diaAno[1].sig = &nEntradas[0];
	diaAno[1].indice = NULL;

	nEntradas[0].tipo_obj = 4;
	nEntradas[0].tipo_de_dato = 0;
	nEntradas[0].acceso = 2;
	memset(nEntradas[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(nEntradas[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(nEntradas[0].oid, "1.3.6.1.3.53.9.6.1.2");
	strcpy(nEntradas[0].instancia, "1.3.6.1.3.53.9.6.1.2.20-12-20");
	nEntradas[0].tipo_valor.val.val_int = 3;
	nEntradas[0].tipo_valor.sig_fila = &nEntradas[1].tipo_valor;
	nEntradas[0].tipo_valor.sig_col = &nSalidas[0].tipo_valor;
	nEntradas[0].sig = &nEntradas[1];
	nEntradas[0].indice = NULL;

	nEntradas[1].tipo_obj = 4;
	nEntradas[1].tipo_de_dato = 0;
	nEntradas[1].acceso = 2;
	memset(nEntradas[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(nEntradas[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(nEntradas[1].oid, "1.3.6.1.3.53.9.6.1.2");
	strcpy(nEntradas[1].instancia, "1.3.6.1.3.53.9.6.1.2.21-12-20");
	nEntradas[1].tipo_valor.val.val_int = 4;
	nEntradas[1].tipo_valor.sig_fila = NULL;
	nEntradas[1].tipo_valor.sig_col = &nSalidas[1].tipo_valor;
	nEntradas[1].sig = &nSalidas[0];
	nEntradas[1].indice = NULL;

	nSalidas[0].tipo_obj = 4;
	nSalidas[0].tipo_de_dato = 0;
	nSalidas[0].acceso = 2;
	memset(nSalidas[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(nSalidas[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(nSalidas[0].oid, "1.3.6.1.3.53.9.6.1.3");
	strcpy(nSalidas[0].instancia, "1.3.6.1.3.53.9.6.1.3.20-12-20");
	nSalidas[0].tipo_valor.val.val_int = 5;
	nSalidas[0].tipo_valor.sig_fila = &nSalidas[1].tipo_valor;
	nSalidas[0].tipo_valor.sig_col = NULL;
	nSalidas[0].sig = &nSalidas[1];
	nSalidas[0].indice = NULL;

	nSalidas[1].tipo_obj = 4;
	nSalidas[1].tipo_de_dato = 0;
	nSalidas[1].acceso = 2;
	memset(nSalidas[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(nSalidas[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(nSalidas[1].oid, "1.3.6.1.3.53.9.6.1.3");
	strcpy(nSalidas[1].instancia, "1.3.6.1.3.53.9.6.1.3.21-12-20");
	nSalidas[1].tipo_valor.val.val_int = 6;
	nSalidas[1].tipo_valor.sig_fila = NULL;
	nSalidas[1].tipo_valor.sig_col = NULL;
	nSalidas[1].sig = &tablaDispositivos;
	nSalidas[1].indice = NULL;

	tablaDispositivos.tipo_obj = 1;
	tablaDispositivos.tipo_de_dato = NULL;
	tablaDispositivos.acceso = 0;
	memset(tablaDispositivos.oid, '\0', MAX_MENSAJE_SNMP);
	memset(tablaDispositivos.instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(tablaDispositivos.oid, "1.3.6.1.3.53.9.7");
	strcpy(tablaDispositivos.instancia, "");
	tablaDispositivos.tipo_valor.val.val_cad = (char*)"";
	tablaDispositivos.tipo_valor.sig_fila = NULL;
	tablaDispositivos.tipo_valor.sig_col = NULL;
	tablaDispositivos.sig = &filaTablaDispositivos;
	tablaDispositivos.indice = NULL;

	filaTablaDispositivos.tipo_obj = 2;
	filaTablaDispositivos.tipo_de_dato = NULL;
	filaTablaDispositivos.acceso = 0;
	memset(filaTablaDispositivos.oid, '\0', MAX_MENSAJE_SNMP);
	memset(filaTablaDispositivos.instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(filaTablaDispositivos.oid, "1.3.6.1.3.53.9.7.1");
	strcpy(filaTablaDispositivos.instancia, "");
	filaTablaDispositivos.tipo_valor.val.val_cad = (char*)"";
	filaTablaDispositivos.tipo_valor.sig_fila = NULL;
	filaTablaDispositivos.tipo_valor.sig_col = NULL;
	filaTablaDispositivos.sig = &ipDispositivo[0];
	filaTablaDispositivos.indice = ipDispositivo;

	ipDispositivo[0].tipo_obj = 4;
	ipDispositivo[0].tipo_de_dato = 1;
	ipDispositivo[0].acceso = 1;
	memset(ipDispositivo[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(ipDispositivo[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(ipDispositivo[0].oid, "1.3.6.1.3.53.9.7.1.1");
	strcpy(ipDispositivo[0].instancia, "1.3.6.1.3.53.9.7.1.1.192.168.1.3");
	ipDispositivo[0].tipo_valor.val.val_cad = (char*)"192.168.1.3";
	ipDispositivo[0].tipo_valor.sig_fila = &ipDispositivo[1].tipo_valor;
	ipDispositivo[0].tipo_valor.sig_col = &modeloDispositivo[0].tipo_valor;
	ipDispositivo[0].sig = &ipDispositivo[1];
	ipDispositivo[0].indice = NULL;

	ipDispositivo[1].tipo_obj = 4;
	ipDispositivo[1].tipo_de_dato = 1;
	ipDispositivo[1].acceso = 1;
	memset(ipDispositivo[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(ipDispositivo[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(ipDispositivo[1].oid, "1.3.6.1.3.53.9.7.1.1");
	strcpy(ipDispositivo[1].instancia, "1.3.6.1.3.53.9.7.1.1.192.168.1.4");
	ipDispositivo[1].tipo_valor.val.val_cad = (char*)"192.168.1.4";
	ipDispositivo[1].tipo_valor.sig_fila = NULL;
	ipDispositivo[1].tipo_valor.sig_col = &modeloDispositivo[1].tipo_valor;
	ipDispositivo[1].sig = &modeloDispositivo[0];
	ipDispositivo[1].indice = NULL;

	modeloDispositivo[0].tipo_obj = 4;
	modeloDispositivo[0].tipo_de_dato = 0;
	modeloDispositivo[0].acceso = 2;
	memset(modeloDispositivo[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(modeloDispositivo[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(modeloDispositivo[0].oid, "1.3.6.1.3.53.9.7.1.2");
	strcpy(modeloDispositivo[0].instancia, "1.3.6.1.3.53.9.7.1.2.192.168.1.3");
	modeloDispositivo[0].tipo_valor.val.val_int = 1;
	modeloDispositivo[0].tipo_valor.sig_fila = &modeloDispositivo[1].tipo_valor;
	modeloDispositivo[0].tipo_valor.sig_col = &tipoTarjeta[0].tipo_valor;
	modeloDispositivo[0].sig = &modeloDispositivo[1];
	modeloDispositivo[0].indice = NULL;

	modeloDispositivo[1].tipo_obj = 4;
	modeloDispositivo[1].tipo_de_dato = 0;
	modeloDispositivo[1].acceso = 2;
	memset(modeloDispositivo[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(modeloDispositivo[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(modeloDispositivo[1].oid, "1.3.6.1.3.53.9.7.1.2");
	strcpy(modeloDispositivo[1].instancia, "1.3.6.1.3.53.9.7.1.2.192.168.1.4");
	modeloDispositivo[1].tipo_valor.val.val_int = 2;
	modeloDispositivo[1].tipo_valor.sig_fila = NULL;
	modeloDispositivo[1].tipo_valor.sig_col = &tipoTarjeta[1].tipo_valor;
	modeloDispositivo[1].sig = &tipoTarjeta[0];
	modeloDispositivo[1].indice = NULL;

	tipoTarjeta[0].tipo_obj = 4;
	tipoTarjeta[0].tipo_de_dato = 0;
	tipoTarjeta[0].acceso = 2;
	memset(tipoTarjeta[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(tipoTarjeta[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(tipoTarjeta[0].oid, "1.3.6.1.3.53.9.7.1.3");
	strcpy(tipoTarjeta[0].instancia, "1.3.6.1.3.53.9.7.1.3.192.168.1.3");
	tipoTarjeta[0].tipo_valor.val.val_int = 1;
	tipoTarjeta[0].tipo_valor.sig_fila = &tipoTarjeta[1].tipo_valor;
	tipoTarjeta[0].tipo_valor.sig_col = &fechaInstalacion[0].tipo_valor;
	tipoTarjeta[0].sig = &tipoTarjeta[1];
	tipoTarjeta[0].indice = NULL;

	tipoTarjeta[1].tipo_obj = 4;
	tipoTarjeta[1].tipo_de_dato = 0;
	tipoTarjeta[1].acceso = 2;
	memset(tipoTarjeta[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(tipoTarjeta[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(tipoTarjeta[1].oid, "1.3.6.1.3.53.9.7.1.3");
	strcpy(tipoTarjeta[1].instancia, "1.3.6.1.3.53.9.7.1.3.192.168.1.4");
	tipoTarjeta[1].tipo_valor.val.val_int = 2;
	tipoTarjeta[1].tipo_valor.sig_fila = NULL;
	tipoTarjeta[1].tipo_valor.sig_col = &fechaInstalacion[1].tipo_valor;
	tipoTarjeta[1].sig = &fechaInstalacion[0];
	tipoTarjeta[1].indice = NULL;

	fechaInstalacion[0].tipo_obj = 4;
	fechaInstalacion[0].tipo_de_dato = 1;
	fechaInstalacion[0].acceso = 2;
	memset(fechaInstalacion[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(fechaInstalacion[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(fechaInstalacion[0].oid, "1.3.6.1.3.53.9.7.1.4");
	strcpy(fechaInstalacion[0].instancia, "1.3.6.1.3.53.9.7.1.4.192.168.1.3");
	fechaInstalacion[0].tipo_valor.val.val_cad = (char*)"20-12-20";
	fechaInstalacion[0].tipo_valor.sig_fila = &fechaInstalacion[1].tipo_valor;
	fechaInstalacion[0].tipo_valor.sig_col = NULL;
	fechaInstalacion[0].sig = &fechaInstalacion[1];
	fechaInstalacion[0].indice = NULL;

	fechaInstalacion[1].tipo_obj = 4;
	fechaInstalacion[1].tipo_de_dato = 1;
	fechaInstalacion[1].acceso = 2;
	memset(fechaInstalacion[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(fechaInstalacion[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(fechaInstalacion[1].oid, "1.3.6.1.3.53.9.7.1.4");
	strcpy(fechaInstalacion[1].instancia, "1.3.6.1.3.53.9.7.1.4.192.168.1.4");
	fechaInstalacion[1].tipo_valor.val.val_cad = (char*)"21-12-20";
	fechaInstalacion[1].tipo_valor.sig_fila = NULL;
	fechaInstalacion[1].tipo_valor.sig_col = NULL;
	fechaInstalacion[1].sig = &tablaRevisiones;
	fechaInstalacion[1].indice = NULL;

	tablaRevisiones.tipo_obj = 1;
	tablaRevisiones.tipo_de_dato = NULL;
	tablaRevisiones.acceso = 0;
	memset(tablaRevisiones.oid, '\0', MAX_MENSAJE_SNMP);
	memset(tablaRevisiones.instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(tablaRevisiones.oid, "1.3.6.1.3.53.9.8");
	strcpy(tablaRevisiones.instancia, "");
	tablaRevisiones.tipo_valor.val.val_cad = (char*)"";
	tablaRevisiones.tipo_valor.sig_fila = NULL;
	tablaRevisiones.tipo_valor.sig_col = NULL;
	tablaRevisiones.sig = &filaTablaRevisiones;
	tablaRevisiones.indice = NULL;

	filaTablaRevisiones.tipo_obj = 2;
	filaTablaRevisiones.tipo_de_dato = NULL;
	filaTablaRevisiones.acceso = 0;
	memset(filaTablaRevisiones.oid, '\0', MAX_MENSAJE_SNMP);
	memset(filaTablaRevisiones.instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(filaTablaRevisiones.oid, "1.3.6.1.3.53.9.8.1");
	strcpy(filaTablaRevisiones.instancia, "");
	filaTablaRevisiones.tipo_valor.val.val_cad = (char*)"";
	filaTablaHistoricos.tipo_valor.sig_fila = NULL;
	filaTablaHistoricos.tipo_valor.sig_col = NULL;
	filaTablaHistoricos.sig = &dia[0];
	filaTablaHistoricos.indice = dia;

	dia[0].tipo_obj = 4;
	dia[0].tipo_de_dato = 0;
	dia[0].acceso = 1;
	memset(dia[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(dia[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(dia[0].oid, "1.3.6.1.3.53.9.8.1.1");
	strcpy(dia[0].instancia, "1.3.6.1.3.53.9.8.1.1.1");
	dia[0].tipo_valor.val.val_int = 1;
	dia[0].tipo_valor.sig_fila = NULL;
	dia[0].tipo_valor.sig_col = NULL;
	dia[0].sig = &dia[1];
	dia[0].indice = NULL;

	dia[1].tipo_obj = 4;
	dia[1].tipo_de_dato = 0;
	dia[1].acceso = 1;
	memset(dia[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(dia[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(dia[1].oid, "1.3.6.1.3.53.9.8.1.1");
	strcpy(dia[1].instancia, "1.3.6.1.3.53.9.8.1.1.2");
	dia[1].tipo_valor.val.val_int = 2;
	dia[1].tipo_valor.sig_fila = NULL;
	dia[1].tipo_valor.sig_col = &nombrePersona[1].tipo_valor;
	dia[1].sig = &nombrePersona[0];
	dia[1].indice = NULL;

	nombrePersona[0].tipo_obj = 4;
	nombrePersona[0].tipo_de_dato = 1;
	nombrePersona[0].acceso = 2;
	memset(nombrePersona[0].oid, '\0', MAX_MENSAJE_SNMP);
	memset(nombrePersona[0].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(nombrePersona[0].oid, "1.3.6.1.3.53.9.8.1.2");
	strcpy(nombrePersona[0].instancia, "1.3.6.1.3.53.9.8.1.2.20-06-20");
	nombrePersona[0].tipo_valor.val.val_cad = (char*)"Alejandro Moreno";
	nombrePersona[0].tipo_valor.sig_fila = &nombrePersona[1].tipo_valor;
	nombrePersona[0].tipo_valor.sig_col = NULL;
	nombrePersona[0].sig = &nombrePersona[1];
	nombrePersona[0].indice = NULL;

	nombrePersona[1].tipo_obj = 4;
	nombrePersona[1].tipo_de_dato = 1;
	nombrePersona[1].acceso = 2;
	memset(nombrePersona[1].oid, '\0', MAX_MENSAJE_SNMP);
	memset(nombrePersona[1].instancia, '\0', MAX_MENSAJE_SNMP);
	strcpy(nombrePersona[1].oid, "1.3.6.1.3.53.9.8.1.2");
	strcpy(nombrePersona[1].instancia, "1.3.6.1.3.53.9.8.1.2.21-12-20");
	nombrePersona[1].tipo_valor.val.val_cad = (char*)"Pablo de Juan";
	nombrePersona[1].tipo_valor.sig_fila = NULL;
	nEntradas[1].tipo_valor.sig_col = NULL;
	nEntradas[1].sig = NULL;
	nEntradas[1].indice = NULL;

	return nombreDispositivo;
}