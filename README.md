Aquí tienes un archivo README actualizado según tus indicaciones:

---

# Proyecto 2: Descifrado por Fuerza Bruta con MPI

Este proyecto implementa un ataque de fuerza bruta para descifrar un texto cifrado utilizando el algoritmo DES. Se han desarrollado versiones secuenciales y paralelas del algoritmo para comparar el rendimiento. Además, una versión utiliza OpenMP para paralelización dentro de los procesos MPI.

## Requisitos

- **Compilador C/C++**
- **OpenMPI**
- **Bibliotecas necesarias**: `openssl`, `mpi.h`, y `omp.h` (solo para la versión con OpenMP)

## Compilación

1. **Versión secuencial:**
   ```bash
   g++ -o bf_seq bf_seq.cpp -lssl -lcrypto
   ```

2. **Versión paralela (MPI):**
   ```bash
   mpic++ -o bf_par bf_par.cpp -lssl -lcrypto
   ```

3. **Versión híbrida (MPI + OpenMP):**
   ```bash
   mpic++ -fopenmp -o openMP openMP.cpp -lssl -lcrypto
   ```

4. **Version secuencial Meet in the middle**
    ```bash
    g++ -o mim_secuencial mim_secuencial.cpp -lssl -lcrypto
    ```

5. **Version paralela Meet in the middle**
    ```bash
    mpic++ -o mim_paralelo mim.cpp -lssl -lcrypto
    ```

## Ejecución

1. **Versión secuencial:**
   ```bash
   ./bf_seq input.t
   ```

2. **Versión paralela (MPI):**
   ```bash
   mpirun -np 4 ./bf_par 
   ```

3. **Versión híbrida (MPI + OpenMP):**
   ```bash
   mpirun -np 4 ./openMP 
   ```

4. **Version secuencial Meet in the middle**
    ```bash
    ./mim_secuencial 
    ```

5. **Version paralela Meet in the middle**
    ```bash
    mpirun -np 4 ./mim 
    ```


