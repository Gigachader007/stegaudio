# Stegaudio

## Описание

Stegaudio - стеганографическая программа, которая позволяет хранить данные непосредственно в аудиофайлах с использованием техники LSB (least significant bit), которая позволяет записывать, читать и изменять данные путём перезаписи младших битов в аудиофайлах, что не влияет на человеческий звук произносимый звук.

## Возможности

- На данный момент программа поддерживает только WAV файлы.
- Программа работает в нескольких режимах: извлечение, добавление, удаление, просмотр список файлов.
- Программа имеет возможность сжатия добавляемых данных с помощью алгоритма LZMA и их шифрование с помощью XChacha20Poly1305 с PBKDF2-SHA256.
- Программа может сразу создать контейнер, добавить данные, извлечь данные, удалить данные в 1 строку.
- Программа может работать с несколькими файлами контейнера сразу.

## Сборка

Для сборки проекта нужен Rust.

```bash
git clone https://github.com/Gigachader007/stegaudio
cd stegaudio
# cargo build для debug сборки
cargo build --release
```

## Исполнение

```bash
./stegaudio --help
```

```
Usage: stegaudio [OPTIONS] --input <INPUT>

Options:
      --input <INPUT>           Input wav file
      --bit-count <BIT_COUNT>   Bit count in LSB encoding/decoding [default: 2]
      --new <NEW>               Create new container inside wav file
                                0 - don't create container
                                1 - create container
                                2 - create container with compression
                                3 - create container with encryption
                                4 - create container with compression and encryption [default: 0]
      --list                    List files in wav file
      --add [<ADD>...]          Add file(s) to wav file
      --remove [<REMOVE>...]    Remove file(s) from wav
      --extract [<EXTRACT>...]  Extract file(s) from wav
  -h, --help
```

## Примеры:

Создадим внутри music.wav зашифрованный контейнер с сжатием и сразу же добавим в него text.txt

```bash
./stegaudio --input music.wav --new 4 --add text.txt
```

```
Write password: 
Adding text.txt to container...
File text.txt added successfully!
```

Выведем содержимое music.wav

```bash
./stegaudio --input music.wav --list
```

```
Write password: 
Files inside container: 
        text.txt

```

Извлечем содержимый файл text.txt и удалим его из music.wav
```bash
./stegaudio --input music.wav --extract text.txt --remove text.txt
```

```
Write password: 
Extracting text.txt...
text.txt extracted successfully!
Successfully text.txt removed!
```

## Тесты
Для запуска тестов достаточно запустить следующую команду.

```bash 
cargo test
```