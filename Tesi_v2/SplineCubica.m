% Specifica il percorso del file CSV
filename = "C:\Users\betpa\Downloads\aesF.csv";  % Sostituisci con il percorso reale del tuo file

% Importa il file CSV come matrice
data = readmatrix(filename);

% Visualizza i dati importati
disp(data);
x = data(:,2)';
y = data(:,3)';

% Definisci i punti in cui vuoi interpolare il segnale
xi = linspace(min(x), max(x), 4000);  % 100 punti equidistanti tra il minimo e il massimo di x

% Calcola i valori interpolati utilizzando la spline cubica
yi = spline(x, y, xi);

% Crea un grafico
plot(x, y, 'o', 'MarkerSize', 8, 'DisplayName', 'Punti Campionati');  % Punti originali
hold on;
plot(xi, yi, '-', 'LineWidth', 2, 'DisplayName', 'Interpolazione Cubica');  % Linea interpolata
title('Interpolazione Cubica con MATLAB');
xlabel('Tempo');
ylabel('Segnale');
legend;
grid on;
