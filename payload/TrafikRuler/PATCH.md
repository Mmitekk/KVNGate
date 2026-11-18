# TrafikRuler 1.1.0 — сборка KVNGate

Бинарник `TrafikRuler.exe` собран из исходников
[li4inka/trafik-ruler](https://github.com/li4inka/trafik-ruler), коммит
`9868c18b3426f8d5c2d34c0b651eaf0956bed7bd` (GPL-3.0), с одним изменением в
`src/TrafikRuler/Core/PacketRouter.cs` — метод `BuildFilter`.

## Что изменено

Из фильтра WinDivert исключены DHCP-пакеты (UDP 67/68 и 546/547). Исходящая
ветка фильтра теперь такая:

```
(outbound and (tcp or (udp and udp.SrcPort != 68 and udp.DstPort != 67 and udp.SrcPort != 546 and udp.DstPort != 547) or (ip and ip.FragOff > 0)))
```

## Зачем

WinDivert перехватывает DHCP-пакеты и отправляет их обратно в стек через
`WinDivertSend`. На виртуальном адаптере SoftEther (`VPN2 - VPN Client`) после
этого клиент не получает адрес: сессия в состоянии Connected, а адаптер остаётся
`169.254.x.x`. Ярлык «Включить» считает такую сессию пустой и перебирает шлюзы,
хотя шлюз живой. Без перехвата DHCP адрес выдаётся за 2–12 секунд, и трафик идёт
через туннель.

## Чего не делать

Вариант `!loopback and not (udp and (...))` эта сборка WinDivert не принимает:
`WinDivertOpen` возвращает `ERROR_INVALID_PARAMETER`, перехват молча не стартует.
Поэтому исключение записано через `!=` внутри UDP-ветки.

## Сборка

1. Взять исходники по ссылке выше.
2. Положить `WinDivert.dll` и `WinDivert64.sys` из этой папки в `native/x64/`.
3. Собрать:

```
dotnet publish src/TrafikRuler/TrafikRuler.csproj -c Release -r win-x64 --self-contained false -o out
```

4. Заменить `TrafikRuler.exe` рядом с этим файлом на `out/TrafikRuler.exe`.
