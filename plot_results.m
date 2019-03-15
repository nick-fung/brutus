yticks = 0:0.1:1;
% Profiling step
for file = dir('results/*.csv')'
  fileName = strrep(file.name, '.csv', '');
  h = figure('name',fileName);

  results = load(strcat('results/',file.name))';
  % Convert frequency to proability distribution
  max_val = max(results);
  results = results / max_val;
  plot(results, 'DisplayName',fileName, 'Linewidth',2);
  title(fileName);
  set(gca,'ytick', yticks);
  xlabel ('Set Size');
  grid on
  % Output to image
  saveas(h,strcat('figures/',fileName),'png');
  
  test_points = zeros(5,1);
  j=1;
  for i = 0.2:0.2:1
    test_points(j) = find(results >= i, 1);
    j = j+1;
  endfor
  csvwrite(file.name,test_points);
end


